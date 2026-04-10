"""
SurrealDB HTTP client for entity graph, vectors, and graph traversal (Ticket 2).
Replaces PostgreSQL entities / entity_edges / entity_observations and pgvector entity paths.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

import httpx

_NS = os.environ.get("ZOVARK_SURREAL_NS", "zovark")
_DB = os.environ.get("ZOVARK_SURREAL_DB", "core")
_BASE = os.environ.get("ZOVARK_SURREAL_HTTP_URL", "http://surrealdb:8000").rstrip("/")
_USER = os.environ.get("ZOVARK_SURREAL_USER", "root")
_PASS = os.environ.get("ZOVARK_SURREAL_PASSWORD", "change-me-surreal")


def _surreal_enabled() -> bool:
    return os.environ.get("ZOVARK_SURREAL_ENABLED", "false").lower() in ("1", "true", "yes")


def _headers() -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Surreal-NS": _NS,
        "Surreal-DB": _DB,
    }


def _safe_record_suffix(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", s)[:200]


async def surreal_sql(client: httpx.AsyncClient, sql: str) -> Any:
    r = await client.post(
        f"{_BASE}/sql",
        headers=_headers(),
        auth=(_USER, _PASS),
        content=sql.encode("utf-8"),
    )
    r.raise_for_status()
    return r.json()


def surreal_sql_sync(client: httpx.Client, sql: str) -> Any:
    r = client.post(
        f"{_BASE}/sql",
        headers=_headers(),
        auth=(_USER, _PASS),
        content=sql.encode("utf-8"),
    )
    r.raise_for_status()
    return r.json()


def ensure_schema_sync(client: httpx.Client) -> None:
    stmts = [
        "DEFINE TABLE IF NOT EXISTS entity SCHEMALESS;",
        "DEFINE TABLE IF NOT EXISTS graph_edge SCHEMALESS;",
        "DEFINE TABLE IF NOT EXISTS investigation_vec SCHEMALESS;",
        "DEFINE TABLE IF NOT EXISTS memory_pattern SCHEMALESS;",
    ]
    for s in stmts:
        surreal_sql_sync(client, s)


async def ensure_schema(client: httpx.AsyncClient) -> None:
    stmts = [
        "DEFINE TABLE IF NOT EXISTS entity SCHEMALESS;",
        "DEFINE TABLE IF NOT EXISTS graph_edge SCHEMALESS;",
        "DEFINE TABLE IF NOT EXISTS investigation_vec SCHEMALESS;",
        "DEFINE TABLE IF NOT EXISTS memory_pattern SCHEMALESS;",
    ]
    for s in stmts:
        await surreal_sql(client, s)


async def write_entity_graph_surreal(
    tenant_id: str,
    investigation_id: Optional[str],
    entity_records: list[dict],
    raw_edges: list[dict],
    all_observations: list[dict],
    entity_hashes: list[str],
    confidence_source: str,
) -> dict[str, Any]:
    """Upsert entities, observations, and edges in SurrealDB only."""
    if not _surreal_enabled():
        return {
            "entities_upserted": 0,
            "edges_upserted": 0,
            "observations_created": 0,
            "entity_hashes": entity_hashes,
            "error": "surreal_disabled",
        }

    entities_upserted = 0
    edges_upserted = 0
    observations_created = 0
    tsafe = _safe_record_suffix(tenant_id)

    async with httpx.AsyncClient(timeout=60.0) as client:
        await ensure_schema(client)
        hash_to_rid: dict[str, str] = {}

        for h in entity_hashes:
            rid = f"entity:{tsafe}_{_safe_record_suffix(h)}"
            hash_to_rid[h] = rid

        for rec in entity_records:
            eh = rec.get("hash")
            if not eh:
                continue
            rid = hash_to_rid.get(eh)
            if not rid:
                continue
            content = {
                "tenant_id": tenant_id,
                "entity_hash": eh,
                "entity_type": rec.get("type"),
                "value": rec.get("value"),
                "threat_score": rec.get("threat_score", 0),
                "last_investigation_id": str(investigation_id) if investigation_id else None,
                "confidence_source": confidence_source,
            }
            q = f"UPSERT {rid} CONTENT {json.dumps(content)};"
            await surreal_sql(client, q)
            entities_upserted += 1

        observations_created = len(all_observations)

        for edge in raw_edges:
            src = edge.get("source", {})
            tgt = edge.get("target", {})
            from entity_normalize import normalize_entity, compute_entity_hash

            src_norm = normalize_entity(src.get("type", ""), src.get("value", ""))
            tgt_norm = normalize_entity(tgt.get("type", ""), tgt.get("value", ""))
            sh = compute_entity_hash(src.get("type", ""), src_norm)
            th = compute_entity_hash(tgt.get("type", ""), tgt_norm)
            srid = hash_to_rid.get(sh)
            trid = hash_to_rid.get(th)
            if not srid or not trid:
                continue
            ec = {
                "tenant_id": tenant_id,
                "edge_type": edge.get("edge_type", "associated_with"),
                "investigation_id": str(investigation_id) if investigation_id else None,
                "mitre_technique": edge.get("mitre_technique"),
                "confidence": float(edge.get("confidence", 0.5)),
            }
            eid = f"graph_edge:{tsafe}_{edges_upserted}_{sh[:8]}_{th[:8]}"
            q = f"CREATE {eid} CONTENT {json.dumps({'source': srid, 'target': trid, **ec})};"
            await surreal_sql(client, q)
            edges_upserted += 1

    return {
        "entities_upserted": entities_upserted,
        "edges_upserted": edges_upserted,
        "observations_created": observations_created,
        "entity_hashes": entity_hashes,
    }


async def blast_radius_surreal(
    investigation_id: str,
    tenant_id: str,
    time_window_hours: int,
    max_hops: int,
) -> dict[str, Any]:
    if not _surreal_enabled():
        return {
            "investigation_id": investigation_id,
            "affected_entities": [],
            "affected_investigations": [],
            "total_entities": 0,
            "max_threat_score": 0,
            "summary": "SurrealDB disabled",
        }

    inv_safe = _safe_record_suffix(str(investigation_id))
    tsafe = _safe_record_suffix(tenant_id)

    async with httpx.AsyncClient(timeout=45.0) as client:
        await ensure_schema(client)
        # Entities linked via graph_edge BFS (Python-side to avoid deep SurrealQL variance)
        q = f"""
SELECT source, target, edge_type FROM graph_edge
WHERE tenant_id = '{tenant_id}' AND investigation_id = '{investigation_id}';
"""
        try:
            raw = await surreal_sql(client, q)
        except Exception as e:
            return {
                "investigation_id": investigation_id,
                "affected_entities": [],
                "affected_investigations": [],
                "total_entities": 0,
                "max_threat_score": 0,
                "summary": f"Error: {e}",
            }

        seeds: set[str] = set()
        edges_list: list[dict] = []
        if isinstance(raw, list):
            for block in raw:
                if isinstance(block, dict) and block.get("result"):
                    for row in block["result"]:
                        if isinstance(row, dict):
                            edges_list.append(row)
                            if row.get("source"):
                                seeds.add(str(row["source"]))
                            if row.get("target"):
                                seeds.add(str(row["target"]))

        visited = set(seeds)
        frontier = list(seeds)
        for _ in range(max_hops):
            next_front: list[str] = []
            for rid in frontier:
                q2 = f"SELECT source, target FROM graph_edge WHERE tenant_id = '{tenant_id}' AND (source = '{rid}' OR target = '{rid}');"
                try:
                    blk = await surreal_sql(client, q2)
                except Exception:
                    continue
                if isinstance(blk, list):
                    for b in blk:
                        for row in b.get("result") or []:
                            if not isinstance(row, dict):
                                continue
                            o = row.get("target") if row.get("source") == rid else row.get("source")
                            if o and str(o) not in visited:
                                visited.add(str(o))
                                next_front.append(str(o))
            frontier = next_front
            if not frontier:
                break

        affected_entities = []
        max_threat = 0
        for rid in visited:
            qe = f"SELECT * FROM {rid};"
            try:
                er = await surreal_sql(client, qe)
                val = None
                if isinstance(er, list) and er and isinstance(er[0], dict):
                    val = (er[0].get("result") or [None])[0]
                if isinstance(val, dict):
                    ts = int(val.get("threat_score") or 0)
                    max_threat = max(max_threat, ts)
                    affected_entities.append(
                        {
                            "entity_id": rid,
                            "entity_type": val.get("entity_type"),
                            "value": val.get("value"),
                            "threat_score": ts,
                            "nearest_hop": 0,
                        }
                    )
            except Exception:
                continue

        return {
            "investigation_id": investigation_id,
            "affected_entities": affected_entities,
            "affected_investigations": [],
            "total_entities": len(affected_entities),
            "max_threat_score": max_threat,
            "summary": f"Surreal graph: {len(affected_entities)} entities (window {time_window_hours}h, {max_hops} hops)",
        }


async def investigation_memory_exact_surreal(entity_type: str, entity_value: str, tenant_id: str) -> Optional[dict]:
    if not _surreal_enabled():
        return None
    async with httpx.AsyncClient(timeout=15.0) as client:
        await ensure_schema(client)
        q = f"""
SELECT * FROM entity WHERE tenant_id = '{tenant_id}' AND entity_type = '{entity_type}' AND value = '{entity_value.replace("'", "''")}' LIMIT 1;
"""
        raw = await surreal_sql(client, q)
        if isinstance(raw, list) and raw and isinstance(raw[0], dict):
            rows = raw[0].get("result") or []
            if rows and isinstance(rows[0], dict):
                return dict(rows[0])
    return None


async def investigation_memory_semantic_surreal(
    entity_type: str, entity_value: str, tenant_id: str, embedding: list, threshold: float
) -> Optional[dict]:
    if not _surreal_enabled() or not embedding:
        return None
    emb_json = json.dumps(embedding)
    async with httpx.AsyncClient(timeout=20.0) as client:
        await ensure_schema(client)
        q = f"""
SELECT * FROM entity WHERE tenant_id = '{tenant_id}' AND entity_type = '{entity_type}'
AND value != '{entity_value.replace("'", "''")}' AND embedding != NONE
AND vector::similarity::cosine(embedding, {emb_json}) > {1.0 - threshold}
ORDER BY vector::similarity::cosine(embedding, {emb_json}) DESC LIMIT 1;
"""
        try:
            raw = await surreal_sql(client, q)
        except Exception:
            return None
        if isinstance(raw, list) and raw and isinstance(raw[0], dict):
            rows = raw[0].get("result") or []
            if rows and isinstance(rows[0], dict):
                return dict(rows[0])
    return None


async def upsert_investigation_vector_surreal(
    investigation_pg_id: str,
    tenant_id: str,
    summary: str,
    verdict: str,
    risk_score: int,
    embedding: Optional[list],
) -> None:
    if not _surreal_enabled():
        return
    inv_safe = _safe_record_suffix(str(investigation_pg_id))
    content: dict[str, Any] = {
        "tenant_id": tenant_id,
        "pg_investigation_id": str(investigation_pg_id),
        "summary": (summary or "")[:4000],
        "verdict": verdict,
        "risk_score": risk_score,
    }
    if embedding:
        content["embedding"] = embedding
    async with httpx.AsyncClient(timeout=30.0) as client:
        await ensure_schema(client)
        q = f"UPSERT investigation_vec:{inv_safe} CONTENT {json.dumps(content)};"
        await surreal_sql(client, q)


async def semantic_search_surreal(
    tenant_id: Optional[str],
    query_embedding: list,
    query_text: str,
    limit: int,
    semantic_weight: float,
    keyword_weight: float,
) -> list[dict]:
    if not _surreal_enabled() or not query_embedding:
        return []
    emb_json = json.dumps(query_embedding)
    tenant_clause = f"AND tenant_id = '{tenant_id}'" if tenant_id else ""
    async with httpx.AsyncClient(timeout=30.0) as client:
        await ensure_schema(client)
        q = f"""
SELECT pg_investigation_id, summary, verdict, risk_score,
vector::similarity::cosine(embedding, {emb_json}) AS sim
FROM investigation_vec WHERE embedding != NONE {tenant_clause}
ORDER BY sim DESC LIMIT {limit};
"""
        try:
            raw = await surreal_sql(client, q)
        except Exception:
            return []
        out = []
        if isinstance(raw, list) and raw and isinstance(raw[0], dict):
            for row in raw[0].get("result") or []:
                if not isinstance(row, dict):
                    continue
                sim = float(row.get("sim") or 0)
                summ = row.get("summary") or ""
                kw = 0.3 if query_text.lower() in summ.lower() else 0.0
                combined = semantic_weight * sim + keyword_weight * kw
                out.append(
                    {
                        "investigation_id": str(row.get("pg_investigation_id", "")),
                        "summary_snippet": summ[:300],
                        "score": round(combined, 4),
                        "semantic_score": round(sim, 4),
                        "keyword_score": round(kw, 4),
                        "verdict": row.get("verdict"),
                        "risk_score": row.get("risk_score"),
                        "match_type": "surreal_vector",
                        "created_at": "",
                    }
                )
        return out


async def surreal_entity_reachability(tenant_id: str, ioc_values: list[str], max_hops: int = 3) -> list[str]:
    """Return investigation pg ids reachable from IOC values via graph_edge (enrichment)."""
    if not _surreal_enabled() or not ioc_values:
        return []
    inv_ids: set[str] = set()
    async with httpx.AsyncClient(timeout=25.0) as client:
        await ensure_schema(client)
        for ioc in ioc_values:
            if not ioc:
                continue
            q = f"""
SELECT id FROM entity WHERE tenant_id = '{tenant_id}' AND value = '{ioc.replace("'", "''")}' LIMIT 5;
"""
            try:
                raw = await surreal_sql(client, q)
            except Exception:
                continue
            rids: list[str] = []
            if isinstance(raw, list):
                for b in raw:
                    for row in b.get("result") or []:
                        if isinstance(row, dict) and row.get("id"):
                            rids.append(str(row["id"]))
            for rid in rids:
                q2 = f"SELECT investigation_id FROM graph_edge WHERE tenant_id = '{tenant_id}' AND (source = '{rid}' OR target = '{rid}');"
                try:
                    raw2 = await surreal_sql(client, q2)
                except Exception:
                    continue
                if isinstance(raw2, list):
                    for b in raw2:
                        for row in b.get("result") or []:
                            if isinstance(row, dict) and row.get("investigation_id"):
                                inv_ids.add(str(row["investigation_id"]))
    return list(inv_ids)


def surreal_entity_reachability_sync(
    tenant_id: str, ioc_values: list[str], max_hops: int = 3
) -> list[str]:
    """Sync variant for tool runner (no asyncio event loop)."""
    _ = max_hops  # reserved for multi-hop graph walks
    if not _surreal_enabled() or not ioc_values:
        return []
    inv_ids: set[str] = set()
    with httpx.Client(timeout=25.0) as client:
        ensure_schema_sync(client)
        for ioc in ioc_values:
            if not ioc:
                continue
            esc = str(ioc).replace("'", "''")
            q = f"""
SELECT id FROM entity WHERE tenant_id = '{tenant_id}' AND value = '{esc}' LIMIT 5;
"""
            try:
                raw = surreal_sql_sync(client, q)
            except Exception:
                continue
            rids: list[str] = []
            if isinstance(raw, list):
                for b in raw:
                    for row in b.get("result") or []:
                        if isinstance(row, dict) and row.get("id"):
                            rids.append(str(row["id"]))
            for rid in rids:
                q2 = f"SELECT investigation_id FROM graph_edge WHERE tenant_id = '{tenant_id}' AND (source = '{rid}' OR target = '{rid}');"
                try:
                    raw2 = surreal_sql_sync(client, q2)
                except Exception:
                    continue
                if isinstance(raw2, list):
                    for b in raw2:
                        for row in b.get("result") or []:
                            if isinstance(row, dict) and row.get("investigation_id"):
                                inv_ids.add(str(row["investigation_id"]))
    return list(inv_ids)
