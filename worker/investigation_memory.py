"""
Investigation Memory — pre-investigation enrichment via SurrealDB (Ticket 2).
Exact match on entity documents; semantic similarity when embeddings exist on entity records.
Verdict/confidence for matched investigations resolved from PostgreSQL investigations (OLTP).
"""
import logging
import os
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

SIMILARITY_THRESHOLDS = {
    "ip": 0.15,
    "domain": 0.20,
    "file_hash": 0.10,
    "user": 0.25,
    "process": 0.20,
    "url": 0.20,
    "email": 0.20,
}

SIMILARITY_OVERRIDE = float(os.environ.get("ZOVARK_SIMILARITY_THRESHOLD", "0"))


def _pg_verdict_for_investigation(db_url: str, investigation_uuid: str) -> tuple:
    if not investigation_uuid:
        return None, None
    try:
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT verdict, confidence FROM investigations
                    WHERE id = %s::uuid
                    ORDER BY created_at DESC NULLS LAST
                    LIMIT 1
                    """,
                    (investigation_uuid,),
                )
                row = cur.fetchone()
                if row:
                    return row.get("verdict"), row.get("confidence")
        finally:
            conn.close()
    except Exception as e:
        logger.warning("PG verdict lookup failed: %s", e)
    return None, None


class InvestigationMemory:
    """Pre-investigation enrichment with SurrealDB entity store + PG verdict lookup."""

    def __init__(self, db_url=None):
        self.db_url = db_url or os.environ.get(
            "DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark"
        )
        self.embed_url = os.environ.get("TEI_URL", "http://embedding-server:80/embed")

    async def enrich_alert(self, alert_entities, tenant_id: str | None = None):
        from surreal_graph import investigation_memory_exact_surreal, investigation_memory_semantic_surreal

        memory = {
            "exact_matches": [],
            "similar_entities": [],
            "related_investigations": set(),
        }

        tid = tenant_id or ""
        if not tid:
            memory["related_investigations"] = []
            return memory

        for entity in alert_entities:
            etype = entity.get("type", "unknown")
            evalue = entity.get("value", "")
            if not evalue:
                continue

            exact = await investigation_memory_exact_surreal(etype, evalue, tid)
            if exact:
                inv_id = exact.get("last_investigation_id")
                verdict, confidence = _pg_verdict_for_investigation(self.db_url, inv_id)
                memory["exact_matches"].append(
                    {
                        "entity": evalue,
                        "type": etype,
                        "conclusion": verdict or "unknown",
                        "confidence": float(confidence or 0),
                        "investigation_id": str(inv_id) if inv_id else "",
                        "seen_at": "",
                        "match_type": "exact",
                    }
                )
                if inv_id:
                    memory["related_investigations"].add(str(inv_id))
                continue

            embedding = await self._get_embedding(evalue)
            similar = await investigation_memory_semantic_surreal(
                etype, evalue, tid, embedding or [], self._get_threshold(etype)
            )
            if similar:
                inv_id = similar.get("last_investigation_id")
                verdict, confidence = _pg_verdict_for_investigation(self.db_url, inv_id)
                memory["similar_entities"].append(
                    {
                        "entity": evalue,
                        "similar_to": similar.get("value", ""),
                        "type": etype,
                        "conclusion": verdict or "unknown",
                        "confidence": float(confidence or 0) * 0.8,
                        "investigation_id": str(inv_id) if inv_id else "",
                        "distance": 1.0 - float(similar.get("sim") or 0),
                        "match_type": "similar",
                    }
                )
                if inv_id:
                    memory["related_investigations"].add(str(inv_id))

        memory["related_investigations"] = list(memory["related_investigations"])
        return memory

    async def _get_embedding(self, text):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(self.embed_url, json={"inputs": text})
                resp.raise_for_status()
                embeddings = resp.json()
                return embeddings[0] if embeddings else None
        except Exception as e:
            logger.warning("Embedding request failed for '%s': %s", text, e)
            return None

    def _get_threshold(self, entity_type):
        if SIMILARITY_OVERRIDE > 0:
            return SIMILARITY_OVERRIDE
        return SIMILARITY_THRESHOLDS.get(entity_type, 0.20)
