"""False positive confidence analyzer — similar investigation lookup + LLM reasoning."""

import os
import json
import time
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity

from security.prompt_sanitizer import wrap_untrusted_data
from llm_logger import log_llm_call
from prompt_registry import get_version
from model_config import get_tier_config


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


@activity.defn
async def analyze_false_positive(data: dict) -> dict:
    """Analyze investigation for false positive confidence.

    Input: {investigation_id, tenant_id, summary, verdict, risk_score, entities}
    Returns: {confidence, verdict, reasoning, evidence, recommendation}
    """
    from entity_graph import search_similar_investigations

    investigation_id = data.get("investigation_id")
    tenant_id = data.get("tenant_id")
    summary = data.get("summary", "")
    verdict = data.get("verdict", "inconclusive")
    risk_score = data.get("risk_score", 0)

    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
    tier_config = get_tier_config("analyze_false_positive")
    llm_model = tier_config["model"]
    tei_url = os.environ.get("TEI_URL", "http://embedding-server:80/embed")

    if not investigation_id or not tenant_id:
        return {"confidence": 0.5, "verdict": verdict, "reasoning": "Missing parameters", "evidence": [], "recommendation": ""}

    # 1. Get embedding for current summary to find similar
    similar_investigations = []
    try:
        if summary:
            async with httpx.AsyncClient(timeout=30.0) as client:
                embed_resp = await client.post(tei_url, json={"inputs": summary[:2000]})
                embed_resp.raise_for_status()
                embed_data = embed_resp.json()
                if isinstance(embed_data, list) and len(embed_data) > 0:
                    embedding = embed_data[0]
                    similar_investigations = search_similar_investigations(tenant_id, embedding, limit=10)
                    # Filter out self
                    similar_investigations = [s for s in similar_investigations if str(s.get("investigation_id")) != str(investigation_id)]
    except Exception as e:
        print(f"FP analyzer: similarity search failed (non-fatal): {e}")

    # 2. Query for entity overlap
    entity_overlap = []
    try:
        conn = _get_db()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT i.id::text as investigation_id, i.verdict, i.risk_score, i.confidence,
                           COUNT(DISTINCT eo.entity_id) as shared_entities
                    FROM investigations i
                    JOIN entity_observations eo ON eo.investigation_id = i.id
                    WHERE eo.entity_id IN (
                        SELECT entity_id FROM entity_observations WHERE investigation_id = %s
                    )
                    AND i.id != %s
                    AND i.tenant_id = %s
                    AND NOT COALESCE(i.injection_detected, false)
                    GROUP BY i.id, i.verdict, i.risk_score, i.confidence
                    HAVING COUNT(DISTINCT eo.entity_id) >= 2
                    ORDER BY shared_entities DESC
                    LIMIT 10
                """, (investigation_id, investigation_id, tenant_id))
                entity_overlap = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        print(f"FP analyzer: entity overlap query failed (non-fatal): {e}")

    # 3. Compute base confidence from similar investigations
    all_similar = similar_investigations + entity_overlap
    confidence = 0.50  # default

    if len(all_similar) >= 5:
        same_verdict = sum(1 for s in all_similar if s.get("verdict") == verdict)
        if same_verdict >= 4:
            confidence = 0.90 + min(same_verdict - 4, 5) * 0.01
        else:
            confidence = 0.50 + (same_verdict / len(all_similar)) * 0.20
    elif len(all_similar) >= 2:
        same_verdict = sum(1 for s in all_similar if s.get("verdict") == verdict)
        confidence = 0.60 + (same_verdict / len(all_similar)) * 0.15
    else:
        confidence = 0.40 + (risk_score / 100.0) * 0.20

    # Cross-tenant boost: entities seen by multiple orgs increase confidence
    cross_tenant_hits = data.get("cross_tenant_hits", 0)
    if cross_tenant_hits >= 3:
        confidence += 0.10
    elif cross_tenant_hits >= 1:
        confidence += 0.05

    confidence = round(min(max(confidence, 0.0), 1.0), 2)

    # 4. LLM reasoning chain
    reasoning = ""
    recommendation = ""
    evidence = [
        {"type": "similar_investigation", "id": str(s.get("investigation_id", "")), "shared_entities": s.get("shared_entities", 0)}
        for s in entity_overlap[:5]
    ]

    try:
        similar_context = json.dumps([
            {"verdict": s.get("verdict"), "risk_score": s.get("risk_score"),
             "similarity": round(float(s.get("similarity", 0)), 3),
             "summary": str(s.get("summary", ""))[:200]}
            for s in similar_investigations[:5]
        ], default=str)

        wrapped_summary, safety_instruction = wrap_untrusted_data(summary[:1500], "investigation")
        wrapped_similar, _ = wrap_untrusted_data(similar_context, "past_investigations")

        system_prompt = (
            "You are a SOC analyst evaluating investigation confidence. "
            "Output valid JSON with: \"reasoning\" (2-3 sentences explaining WHY this verdict is correct, "
            "referencing specific evidence from past investigations), "
            "\"recommendation\" (1 sentence actionable next step). "
            f"{safety_instruction}"
        )

        user_prompt = (
            f"Current investigation verdict: {verdict}, risk_score: {risk_score}, confidence: {confidence}\n\n"
            f"Current investigation:\n{wrapped_summary}\n\n"
            f"Similar past investigations:\n{wrapped_similar}\n\n"
            f"Entity overlap count: {len(entity_overlap)} investigations share 2+ entities\n\n"
            f"Explain why the verdict '{verdict}' is appropriate based on the evidence."
        )

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                litellm_url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": llm_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 512,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            result = resp.json()

            usage = result.get("usage", {})
            log_llm_call(
                activity_name="analyze_false_positive",
                model_tier=tier_config["tier"],
                model_id=llm_model,
                prompt_name="fp_analysis",
                prompt_version=get_version("fp_analysis"),
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
                latency_ms=0,
                temperature=tier_config["temperature"],
                max_tokens=tier_config["max_tokens"],
                tenant_id=tenant_id,
            )

            content = result["choices"][0]["message"]["content"].strip()

            try:
                parsed = json.loads(content)
                reasoning = parsed.get("reasoning", content[:300])
                recommendation = parsed.get("recommendation", "")
            except json.JSONDecodeError:
                reasoning = content[:300]
    except Exception as e:
        print(f"FP analyzer: LLM reasoning failed (non-fatal): {e}")
        reasoning = f"Confidence {confidence} based on {len(all_similar)} similar investigations"

    # 5. Update investigation confidence + feedback
    try:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL synchronous_commit = on")
                feedback = json.dumps({
                    "fp_analysis": {
                        "confidence": confidence,
                        "reasoning": reasoning,
                        "evidence": evidence,
                        "recommendation": recommendation,
                        "similar_count": len(similar_investigations),
                        "overlap_count": len(entity_overlap),
                    }
                })
                cur.execute("""
                    UPDATE investigations
                    SET confidence = %s, analyst_feedback = %s
                    WHERE id = %s
                """, (confidence, feedback, investigation_id))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"FP analyzer: DB update failed (non-fatal): {e}")

    print(f"FP analysis for {investigation_id}: confidence={confidence}, similar={len(similar_investigations)}, overlap={len(entity_overlap)}")

    return {
        "confidence": confidence,
        "verdict": verdict,
        "reasoning": reasoning,
        "evidence": evidence,
        "recommendation": recommendation,
    }
