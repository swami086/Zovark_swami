"""Bootstrap Temporal activities: load MITRE, load CISA, generate synthetic, process entities."""

import os
import json
import time
import httpx
import psycopg2
from psycopg2.extras import execute_values, RealDictCursor
from temporalio import activity

from bootstrap.mitre_parser import parse_mitre_stix
from bootstrap.cisa_parser import parse_cisa_kev
from llm_logger import log_llm_call
from prompt_registry import get_version
from model_config import get_tier_config


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


def _sync_commit(cur):
    cur.execute("SET LOCAL synchronous_commit = on")


@activity.defn
async def load_mitre_techniques(data: dict) -> dict:
    """Parse MITRE STIX bundle, batch insert techniques, embed descriptions.

    Input: {stix_path: str}
    Returns: {techniques_loaded, embeddings_created}
    """
    stix_path = data.get("stix_path", "/app/bootstrap_data/mitre/enterprise-attack.json")
    tei_url = os.environ.get("TEI_URL", "http://embedding-server:80/embed")
    batch_size = data.get("embedding_batch_size", 32)

    techniques = parse_mitre_stix(stix_path)
    print(f"Parsed {len(techniques)} MITRE techniques")

    if not techniques:
        return {"techniques_loaded": 0, "embeddings_created": 0}

    conn = _get_db()
    embeddings_created = 0
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)

            # Batch upsert techniques (without embeddings first)
            values = [
                (
                    t["technique_id"], t["name"], t["description"],
                    t["tactics"], t["platforms"],
                    t["data_sources"], t["detection"], t["url"]
                )
                for t in techniques
            ]
            execute_values(
                cur,
                """INSERT INTO mitre_techniques
                   (technique_id, name, description, tactics, platforms, data_sources, detection, url)
                   VALUES %s
                   ON CONFLICT (technique_id) DO UPDATE SET
                       name = EXCLUDED.name,
                       description = EXCLUDED.description,
                       tactics = EXCLUDED.tactics,
                       platforms = EXCLUDED.platforms,
                       data_sources = EXCLUDED.data_sources,
                       detection = EXCLUDED.detection,
                       url = EXCLUDED.url""",
                values,
                template="(%s, %s, %s, %s, %s, %s, %s, %s)"
            )
            print(f"Upserted {len(values)} techniques")

        conn.commit()

        # Embed descriptions in batches
        for i in range(0, len(techniques), batch_size):
            batch = techniques[i:i + batch_size]
            texts = [
                f"{t['technique_id']}: {t['name']}. {t['description'][:500]}"
                for t in batch
            ]

            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    resp = await client.post(tei_url, json={"inputs": texts})
                    resp.raise_for_status()
                    embeddings = resp.json()

                if isinstance(embeddings, list) and len(embeddings) == len(batch):
                    with conn.cursor() as cur:
                        for j, t in enumerate(batch):
                            emb = embeddings[j]
                            if isinstance(emb, list) and len(emb) > 0:
                                # Handle nested list (TEI returns [[float...]])
                                if isinstance(emb[0], list):
                                    emb = emb[0]
                                cur.execute(
                                    "UPDATE mitre_techniques SET embedding = %s::vector WHERE technique_id = %s",
                                    (emb, t["technique_id"])
                                )
                                embeddings_created += 1
                    conn.commit()
                    print(f"Embedded batch {i // batch_size + 1}: {len(batch)} techniques")
            except Exception as e:
                print(f"Embedding batch {i // batch_size + 1} failed (non-fatal): {e}")

    finally:
        conn.close()

    return {"techniques_loaded": len(techniques), "embeddings_created": embeddings_created}


@activity.defn
async def load_cisa_kev(data: dict) -> dict:
    """Parse CISA KEV JSON, insert into bootstrap_corpus.

    Input: {kev_path: str}
    Returns: {vulnerabilities_loaded}
    """
    kev_path = data.get("kev_path", "/app/bootstrap_data/cisa/known_exploited_vulnerabilities.json")

    vulns = parse_cisa_kev(kev_path)
    print(f"Parsed {len(vulns)} CISA KEV entries")

    if not vulns:
        return {"vulnerabilities_loaded": 0}

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            values = [
                (
                    "cisa", v["cve_id"],
                    f"{v['vendor']} {v['product']}: {v['name']}",
                    v["description"]
                )
                for v in vulns
            ]
            execute_values(
                cur,
                """INSERT INTO bootstrap_corpus (source, source_id, title, description)
                   VALUES %s
                   ON CONFLICT DO NOTHING""",
                values,
                template="(%s, %s, %s, %s)"
            )
        conn.commit()
    finally:
        conn.close()

    return {"vulnerabilities_loaded": len(vulns)}


@activity.defn
async def generate_synthetic_investigation(data: dict) -> dict:
    """Generate a synthetic SOC investigation for a MITRE technique or CISA CVE.

    Input: {source: 'mitre'|'cisa', source_id, title, description, technique_id?}
    Returns: {source_id, investigation_length, tokens_used}
    """
    llm_endpoint = os.environ.get("ZOVARK_LLM_ENDPOINT", "http://host.docker.internal:11434/v1/chat/completions")
    api_key = os.environ.get("ZOVARK_LLM_KEY", "zovark-llm-key-2026")
    tier_config = get_tier_config("generate_synthetic_investigation")
    llm_model = tier_config["model"]

    source = data.get("source", "mitre")
    source_id = data.get("source_id", "")
    title = data.get("title", "")
    description = data.get("description", "")[:800]

    system_prompt = (
        "You are a SOC analyst writing an investigation summary. "
        "Output valid JSON with: findings (array), iocs (array of {type, value}), "
        "verdict (true_positive/false_positive/suspicious), risk_score (0-100), "
        "mitre_techniques (array of technique IDs), recommendations (array). "
        "Be concise. Use realistic but fictional IPs/domains/hashes."
    )

    if source == "mitre":
        user_prompt = (
            f"Write an investigation summary for a detected attack using MITRE technique "
            f"{source_id} ({title}).\nDescription: {description}\n"
            f"Include realistic log analysis findings, IOCs found, and a verdict."
        )
    else:
        user_prompt = (
            f"Write an investigation summary for exploitation of {source_id} ({title}).\n"
            f"Description: {description}\n"
            f"Include realistic log analysis findings, IOCs found, and a verdict."
        )

    start_time = time.time()
    tokens_used = 0
    investigation_text = ""

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                llm_endpoint,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": llm_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.8,
                    "max_tokens": 1024,
                    "response_format": {"type": "json_object"}
                }
            )
            resp.raise_for_status()
            result = resp.json()
            usage = result.get("usage", {})
            tokens_used = usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)
            investigation_text = result["choices"][0]["message"]["content"].strip()

            log_llm_call(
                activity_name="generate_synthetic_investigation",
                model_tier=tier_config["tier"],
                model_id=llm_model,
                prompt_name="synthetic_investigation",
                prompt_version=get_version("synthetic_investigation"),
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
                latency_ms=int((time.time() - start_time) * 1000),
                temperature=0.8,
                max_tokens=tier_config["max_tokens"],
            )
    except Exception as e:
        print(f"LLM call failed for {source_id}: {e}")
        log_llm_call(
            activity_name="generate_synthetic_investigation",
            model_tier=tier_config["tier"],
            model_id=llm_model,
            prompt_name="synthetic_investigation",
            prompt_version=get_version("synthetic_investigation"),
            latency_ms=int((time.time() - start_time) * 1000),
            status="error",
            error_message=str(e),
        )
        return {"source_id": source_id, "investigation_length": 0, "tokens_used": 0, "error": str(e)}

    # Store in bootstrap_corpus
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                UPDATE bootstrap_corpus
                SET generated_investigation = %s, status = 'generating'
                WHERE source_id = %s AND source = %s
            """, (investigation_text, source_id, source))

            # If no row existed (MITRE techniques don't have corpus rows yet), insert
            if cur.rowcount == 0:
                cur.execute("""
                    INSERT INTO bootstrap_corpus (source, source_id, title, description, generated_investigation, status)
                    VALUES (%s, %s, %s, %s, %s, 'generating')
                    ON CONFLICT DO NOTHING
                """, (source, source_id, title, description[:500], investigation_text))
        conn.commit()
    finally:
        conn.close()

    execution_ms = int((time.time() - start_time) * 1000)
    print(f"Generated investigation for {source_id}: {len(investigation_text)} chars, {tokens_used} tokens, {execution_ms}ms")

    return {
        "source_id": source_id,
        "investigation_length": len(investigation_text),
        "tokens_used": tokens_used,
    }


@activity.defn
async def process_bootstrap_entity(data: dict) -> dict:
    """Extract entities from a bootstrap investigation and write to entity graph.

    Input: {source_id, source, tenant_id}
    Returns: {entities, edges, investigation_id}
    """
    from entity_graph import extract_entities, write_entity_graph, embed_investigation

    source_id = data.get("source_id", "")
    source = data.get("source", "mitre")
    tenant_id = data.get("tenant_id")

    # Fetch the generated investigation
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, generated_investigation, title FROM bootstrap_corpus WHERE source_id = %s AND source = %s",
                (source_id, source)
            )
            row = cur.fetchone()
            if not row:
                return {"entities": 0, "edges": 0, "investigation_id": None, "error": "not found"}
            corpus_id, investigation_text, title = row
    finally:
        conn.close()

    if not investigation_text:
        return {"entities": 0, "edges": 0, "investigation_id": None, "error": "no investigation text"}

    # 1. Extract entities (reuse existing activity logic directly)
    entity_result = await extract_entities({
        "investigation_output": investigation_text,
        "task_type": "bootstrap",
        "tenant_id": tenant_id,
        "task_id": str(corpus_id),
    })

    entities = entity_result.get("entities", [])
    edges = entity_result.get("edges", [])

    # 2. Embed investigation + create investigations row
    # Parse risk_score from generated investigation if possible
    risk_score = 50
    verdict = "suspicious"
    techniques = []
    try:
        parsed = json.loads(investigation_text)
        risk_score = int(parsed.get("risk_score", 50))
        verdict = parsed.get("verdict", "suspicious")
        techniques = parsed.get("mitre_techniques", [])
    except Exception:
        pass

    embed_result = await embed_investigation({
        "tenant_id": tenant_id,
        "task_id": None,
        "summary": investigation_text[:2000],
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": min(risk_score / 100.0, 1.0),
        "attack_techniques": techniques,
        "source": "bootstrap",
        "model_id": "fast",
        "prompt_version": "1f",
    })

    investigation_id = embed_result.get("investigation_id")

    # 3. Write entity graph
    entity_count = 0
    edge_count = 0
    if entities and investigation_id:
        graph_result = await write_entity_graph({
            "tenant_id": tenant_id,
            "task_id": str(corpus_id),
            "investigation_id": investigation_id,
            "entities": entities,
            "edges": edges,
        })
        entity_count = graph_result.get("entities_upserted", 0)
        edge_count = graph_result.get("edges_upserted", 0)

    # 4. Update bootstrap_corpus status
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                UPDATE bootstrap_corpus SET status = 'completed', entity_count = %s
                WHERE source_id = %s AND source = %s
            """, (entity_count, source_id, source))
        conn.commit()
    finally:
        conn.close()

    print(f"Processed {source_id}: {entity_count} entities, {edge_count} edges, inv={investigation_id}")

    return {
        "entities": entity_count,
        "edges": edge_count,
        "investigation_id": investigation_id,
    }


@activity.defn
async def list_techniques(data: dict) -> list:
    """List MITRE techniques from DB for workflow processing."""
    limit = data.get("limit", 50)
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT technique_id, name, LEFT(description, 800) as description
                FROM mitre_techniques
                ORDER BY technique_id
                LIMIT %s
            """, (limit,))
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
