"""Entity graph Temporal activities: extract, write, embed + similarity search.

Three @activity.defn activities following existing patterns from activities.py.
"""

import os
import re
import json
import time
import httpx
import psycopg2
from psycopg2.extras import execute_values, RealDictCursor
from temporalio import activity

from entity_normalize import normalize_entity, compute_entity_hash
from prompts.entity_extraction import ENTITY_EXTRACTION_SYSTEM_PROMPT, build_entity_extraction_prompt
from llm_logger import log_llm_call
from prompt_registry import get_version
from model_config import get_tier_config


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
    return psycopg2.connect(db_url)


def _sync_commit(cur):
    """Enable synchronous commit for this transaction (critical writes)."""
    cur.execute("SET LOCAL synchronous_commit = on")


# --- Regex fallback patterns for entity extraction when LLM JSON is malformed ---
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
_HASH_RE = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
_EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

# Common false-positive domains to skip
_DOMAIN_SKIP = frozenset({
    'example.com', 'localhost.localdomain', 'python.org',
    'github.com', 'googleapis.com', 'json.org',
})

VALID_ENTITY_TYPES = frozenset({'ip', 'domain', 'file_hash', 'url', 'user', 'device', 'process', 'email'})
VALID_ROLES = frozenset({'source', 'destination', 'attacker', 'victim', 'indicator', 'artifact', 'infrastructure', 'target'})
VALID_EDGE_TYPES = frozenset({
    'communicates_with', 'resolved_to', 'logged_into',
    'executed', 'downloaded', 'contains', 'parent_of',
    'accessed', 'sent_to', 'received_from', 'associated_with'
})


def _regex_extract_entities(text: str) -> list:
    """Fallback: extract entities via regex when LLM output is malformed."""
    entities = []
    seen = set()

    for ip in _IP_RE.findall(text):
        if ip not in seen:
            entities.append({"type": "ip", "value": ip, "role": "indicator", "context": "regex-extracted", "mitre_technique": None})
            seen.add(ip)

    for domain in _DOMAIN_RE.findall(text):
        d = domain.lower()
        if d not in seen and d not in _DOMAIN_SKIP and not d.endswith('.py') and not d.endswith('.json'):
            entities.append({"type": "domain", "value": d, "role": "indicator", "context": "regex-extracted", "mitre_technique": None})
            seen.add(d)

    for h in _HASH_RE.findall(text):
        h_lower = h.lower()
        if h_lower not in seen and len(h_lower) in (32, 40, 64):
            entities.append({"type": "file_hash", "value": h_lower, "role": "indicator", "context": "regex-extracted", "mitre_technique": None})
            seen.add(h_lower)

    for email in _EMAIL_RE.findall(text):
        e = email.lower()
        if e not in seen:
            entities.append({"type": "email", "value": e, "role": "indicator", "context": "regex-extracted", "mitre_technique": None})
            seen.add(e)

    return entities


def _validate_entity(e: dict) -> bool:
    """Validate a single entity dict has required fields and valid values."""
    return (
        isinstance(e, dict)
        and e.get("type") in VALID_ENTITY_TYPES
        and isinstance(e.get("value"), str)
        and len(e["value"].strip()) > 0
    )


def _validate_edge(edge: dict) -> bool:
    """Validate a single edge dict."""
    return (
        isinstance(edge, dict)
        and isinstance(edge.get("source"), dict)
        and isinstance(edge.get("target"), dict)
        and edge.get("edge_type") in VALID_EDGE_TYPES
        and edge["source"].get("type") in VALID_ENTITY_TYPES
        and edge["target"].get("type") in VALID_ENTITY_TYPES
    )


@activity.defn
async def extract_entities(data: dict) -> dict:
    """Call LiteLLM with entity extraction prompt, parse structured response.

    Input: {investigation_output, task_type, tenant_id, task_id}
    Returns: {entities, edges, usage_tokens, execution_ms}
    """
    # FAST_FILL: skip LLM, return empty entities (regex fallback handles it)
    if os.environ.get('ZOVARC_FAST_FILL', '') == 'true':
        return {"entities": [], "edges": [], "usage_tokens": {"prompt_tokens": 0, "completion_tokens": 0}, "execution_ms": 0}

    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-zovarc-dev-2026")
    tier_config = get_tier_config("extract_entities")
    llm_model = tier_config["model"]

    investigation_output = data.get("investigation_output", "")
    task_type = data.get("task_type", "unknown")

    user_prompt = build_entity_extraction_prompt(investigation_output, task_type)

    start_time = time.time()
    usage_tokens = {"prompt_tokens": 0, "completion_tokens": 0}
    entities = []
    edges = []
    llm_status = "success"

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                litellm_url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": llm_model,
                    "messages": [
                        {"role": "system", "content": ENTITY_EXTRACTION_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": tier_config["temperature"],
                    "max_tokens": tier_config["max_tokens"],
                    "response_format": {"type": "json_object"}
                }
            )
            resp.raise_for_status()
            result = resp.json()
            usage_tokens = result.get("usage", usage_tokens)

            content = result["choices"][0]["message"]["content"].strip()
            parsed = json.loads(content)

            raw_entities = parsed.get("entities", [])
            raw_edges = parsed.get("edges", [])

            entities = [e for e in raw_entities if _validate_entity(e)]
            edges = [e for e in raw_edges if _validate_edge(e)]

    except (json.JSONDecodeError, KeyError, httpx.HTTPError) as e:
        print(f"Entity extraction LLM failed, falling back to regex: {e}")
        entities = _regex_extract_entities(investigation_output)
        llm_status = "fallback"
    except Exception as e:
        print(f"Entity extraction unexpected error, falling back to regex: {e}")
        entities = _regex_extract_entities(investigation_output)
        llm_status = "error"

    execution_ms = int((time.time() - start_time) * 1000)

    log_llm_call(
        activity_name="extract_entities",
        model_tier=tier_config["tier"],
        model_id=llm_model,
        prompt_name="entity_extraction",
        prompt_version=get_version("entity_extraction"),
        input_tokens=usage_tokens.get("prompt_tokens", 0),
        output_tokens=usage_tokens.get("completion_tokens", 0),
        latency_ms=execution_ms,
        status=llm_status,
        temperature=tier_config["temperature"],
        max_tokens=tier_config["max_tokens"],
        tenant_id=data.get("tenant_id"),
        task_id=data.get("task_id"),
    )

    return {
        "entities": entities,
        "edges": edges,
        "usage_tokens": usage_tokens,
        "execution_ms": execution_ms
    }


@activity.defn
async def write_entity_graph(data: dict) -> dict:
    """Normalize entities, compute hashes, batch upsert to DB.

    Input: {tenant_id, task_id, investigation_id, entities, edges, confidence_source}
    Returns: {entities_upserted, edges_upserted, observations_created}
    """
    tenant_id = data.get("tenant_id")
    data.get("task_id")
    investigation_id = data.get("investigation_id")
    raw_entities = data.get("entities", [])
    raw_edges = data.get("edges", [])
    confidence_source = data.get("confidence_source", "clean")

    entities_upserted = 0
    edges_upserted = 0
    observations_created = 0
    entity_hashes = []

    try:
        # Normalize, compute hashes, and deduplicate
        hash_to_entity = {}
        all_observations = []  # track all observations including duplicates
        for e in raw_entities:
            etype = e["type"]
            normalized = normalize_entity(etype, e["value"])
            ehash = compute_entity_hash(etype, normalized)
            record = {
                "hash": ehash,
                "type": etype,
                "value": normalized,
                "role": e.get("role", "indicator"),
                "context": e.get("context", ""),
                "mitre_technique": e.get("mitre_technique"),
            }
            all_observations.append(record)
            # Deduplicate: keep first occurrence per hash for entity upsert
            if ehash not in hash_to_entity:
                hash_to_entity[ehash] = record
        entity_records = list(hash_to_entity.values())
        entity_hashes = list(hash_to_entity.keys())

        if not entity_records:
            return {"entities_upserted": 0, "edges_upserted": 0, "observations_created": 0}

        conn = _get_db()
        try:
            with conn.cursor() as cur:
                _sync_commit(cur)
                # 1. Batch upsert entities
                entity_values = [
                    (r["hash"], r["type"], r["value"], tenant_id)
                    for r in entity_records
                ]
                execute_values(
                    cur,
                    """INSERT INTO entities (entity_hash, entity_type, value, tenant_id)
                       VALUES %s
                       ON CONFLICT (entity_hash, tenant_id) DO UPDATE SET
                           last_seen = NOW(),
                           observation_count = entities.observation_count + 1""",
                    entity_values,
                    template="(%s, %s, %s, %s)"
                )
                entities_upserted = len(entity_values)

                # 2. Fetch hash -> id mapping for this tenant
                hashes = [r["hash"] for r in entity_records]
                cur.execute(
                    "SELECT id, entity_hash FROM entities WHERE entity_hash = ANY(%s) AND tenant_id = %s",
                    (hashes, tenant_id)
                )
                hash_id_map = {row[1]: str(row[0]) for row in cur.fetchall()}

                # 3. Insert observations (one per entity mention, not deduplicated)
                obs_values = []
                for r in all_observations:
                    eid = hash_id_map.get(r["hash"])
                    if eid:
                        role = r["role"] if r["role"] in VALID_ROLES else "indicator"
                        obs_values.append((
                            eid, investigation_id, role,
                            r.get("context", ""), r.get("mitre_technique"),
                            confidence_source
                        ))
                if obs_values:
                    execute_values(
                        cur,
                        """INSERT INTO entity_observations (entity_id, investigation_id, role, context, mitre_technique, confidence_source)
                           VALUES %s""",
                        obs_values,
                        template="(%s, %s, %s, %s, %s, %s)"
                    )
                    observations_created = len(obs_values)

                # Flag investigation if injection detected
                if confidence_source == "injection_detected" and investigation_id:
                    cur.execute(
                        "UPDATE investigations SET injection_detected = true WHERE id = %s",
                        (investigation_id,)
                    )

                # 4. Resolve and insert edges
                edge_values = []
                for edge in raw_edges:
                    src = edge.get("source", {})
                    tgt = edge.get("target", {})
                    src_norm = normalize_entity(src.get("type", ""), src.get("value", ""))
                    tgt_norm = normalize_entity(tgt.get("type", ""), tgt.get("value", ""))
                    src_hash = compute_entity_hash(src.get("type", ""), src_norm)
                    tgt_hash = compute_entity_hash(tgt.get("type", ""), tgt_norm)
                    src_id = hash_id_map.get(src_hash)
                    tgt_id = hash_id_map.get(tgt_hash)
                    if src_id and tgt_id:
                        edge_values.append((
                            src_id, tgt_id, edge["edge_type"],
                            investigation_id, tenant_id,
                            edge.get("mitre_technique"),
                            edge.get("confidence", 0.5)
                        ))
                if edge_values:
                    execute_values(
                        cur,
                        """INSERT INTO entity_edges
                           (source_entity_id, target_entity_id, edge_type, investigation_id, tenant_id, mitre_technique, confidence)
                           VALUES %s""",
                        edge_values,
                        template="(%s, %s, %s, %s, %s, %s, %s)"
                    )
                    edges_upserted = len(edge_values)

            conn.commit()
        finally:
            conn.close()

    except Exception as e:
        print(f"write_entity_graph non-fatal error: {e}")

    return {
        "entities_upserted": entities_upserted,
        "edges_upserted": edges_upserted,
        "observations_created": observations_created,
        "entity_hashes": entity_hashes,
    }


@activity.defn
async def embed_investigation(data: dict) -> dict:
    """Create investigations row with verdict, risk_score, embedding.

    Input: {tenant_id, task_id, summary, verdict, risk_score, confidence,
            attack_techniques, skill_id, skill_version, model_id, model_version,
            prompt_version, source, task_type}
    Returns: {investigation_id, embedding_dim, execution_ms}
    """
    # FAST_FILL: skip embedding, still write the investigation row
    if os.environ.get('ZOVARC_FAST_FILL', '') == 'true':
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                _sync_commit(cur)
                cur.execute("""
                    INSERT INTO investigations
                    (tenant_id, task_id, verdict, risk_score, confidence,
                     attack_techniques, summary, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (data.get("tenant_id"), data.get("task_id"),
                      data.get("verdict", "inconclusive"), data.get("risk_score", 0),
                      data.get("confidence", 0.5), data.get("attack_techniques", []),
                      data.get("summary", "")[:2000], data.get("source", "fast_fill")))
                row = cur.fetchone()
                inv_id = str(row[0]) if row else None
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"embed_investigation FAST_FILL db error: {e}")
            inv_id = None
        finally:
            conn.close()
        return {"investigation_id": inv_id, "embedding_dim": 0, "execution_ms": 0}

    tei_url = os.environ.get("TEI_URL", "http://embedding-server:80/embed")

    tenant_id = data.get("tenant_id")
    task_id = data.get("task_id")
    summary = data.get("summary", "")
    verdict = data.get("verdict", "inconclusive")
    risk_score = data.get("risk_score", 0)
    confidence = data.get("confidence", 0.5)
    attack_techniques = data.get("attack_techniques", [])
    skill_id = data.get("skill_id")
    skill_version = data.get("skill_version")
    model_id = data.get("model_id", "fast")
    model_version = data.get("model_version")
    prompt_version = data.get("prompt_version", "1g")
    source = data.get("source", "production")

    start_time = time.time()
    embedding = None
    embedding_dim = 0

    try:
        # Get embedding for summary
        if summary:
            async with httpx.AsyncClient(timeout=30.0) as client:
                embed_resp = await client.post(tei_url, json={"inputs": summary})
                embed_resp.raise_for_status()
                embed_data = embed_resp.json()
                if isinstance(embed_data, list) and len(embed_data) > 0:
                    embedding = embed_data[0]
                    embedding_dim = len(embedding)
    except Exception as e:
        print(f"embed_investigation: embedding call failed (non-fatal): {e}")

    investigation_id = None
    try:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                _sync_commit(cur)
                cur.execute("""
                    INSERT INTO investigations
                    (tenant_id, task_id, verdict, risk_score, confidence,
                     attack_techniques, skill_id, skill_version,
                     summary, summary_embedding,
                     model_id, model_version, prompt_version, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::vector, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    tenant_id, task_id, verdict, risk_score, confidence,
                    attack_techniques, skill_id, skill_version,
                    summary, embedding,
                    model_id, model_version, prompt_version, source
                ))
                row = cur.fetchone()
                investigation_id = str(row[0]) if row else None
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"embed_investigation: DB insert failed (non-fatal): {e}")

    execution_ms = int((time.time() - start_time) * 1000)
    return {
        "investigation_id": investigation_id,
        "embedding_dim": embedding_dim,
        "execution_ms": execution_ms
    }


def search_similar_investigations(tenant_id: str, embedding: list, limit: int = 10) -> list:
    """Utility: pgvector cosine similarity search on investigations.

    Args:
        tenant_id: Filter by tenant
        embedding: 768-dim vector
        limit: Max results

    Returns:
        List of dicts with investigation_id, summary, similarity, verdict, risk_score
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id AS investigation_id, summary, verdict, risk_score,
                       1 - (summary_embedding <=> %s::vector) AS similarity
                FROM investigations
                WHERE tenant_id = %s
                  AND summary_embedding IS NOT NULL
                  AND NOT COALESCE(injection_detected, false)
                ORDER BY summary_embedding <=> %s::vector
                LIMIT %s
            """, (embedding, tenant_id, embedding, limit))
            results = cur.fetchall()
            return [dict(r) for r in results]
    finally:
        conn.close()
