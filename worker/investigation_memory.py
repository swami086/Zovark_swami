"""
Investigation Memory — Pre-investigation enrichment.
Two-pass matching: exact first, then pgvector semantic search.
Wired into ExecuteTaskWorkflow as Step 0.

CTO CORRECTIONS APPLIED:
- NO CIDR normalization for IPs (exact match only in Pass 1)
- Per-entity-type similarity thresholds (tunable, logged)
- pgvector distance threshold NOT hardcoded — configurable
"""
import logging
import os
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Tunable per entity type — log every match to calibrate during pilot
SIMILARITY_THRESHOLDS = {
    'ip': 0.15,
    'domain': 0.20,
    'file_hash': 0.10,
    'user': 0.25,
    'process': 0.20,
    'url': 0.20,
    'email': 0.20,
}

# Override from env if needed
SIMILARITY_OVERRIDE = float(os.environ.get('ZOVARC_SIMILARITY_THRESHOLD', '0'))


class InvestigationMemory:
    """Pre-investigation enrichment with exact + semantic matching."""

    def __init__(self, db_url=None):
        self.db_url = db_url or os.environ.get(
            "DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc"
        )
        self.litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
        self.litellm_key = os.environ.get("LITELLM_MASTER_KEY", "sk-zovarc-dev-2026")
        self.embed_url = os.environ.get("TEI_URL", "http://embedding-server:80/embed")

    async def enrich_alert(self, alert_entities):
        """
        Two-pass enrichment for extracted alert IOCs.
        Returns: {exact_matches: [...], similar_entities: [...], related_investigations: [...]}
        """
        memory = {
            'exact_matches': [],
            'similar_entities': [],
            'related_investigations': set()
        }

        conn = psycopg2.connect(self.db_url)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                for entity in alert_entities:
                    etype = entity.get('type', 'unknown')
                    evalue = entity.get('value', '')
                    if not evalue:
                        continue

                    # PASS 1: Exact value match (high confidence, fast)
                    exact = self._exact_match(cur, etype, evalue)
                    if exact:
                        memory['exact_matches'].append({
                            'entity': evalue,
                            'type': etype,
                            'conclusion': exact['verdict'],
                            'confidence': float(exact['confidence'] or 0),
                            'investigation_id': str(exact['investigation_id']),
                            'seen_at': str(exact['created_at']),
                            'match_type': 'exact'
                        })
                        memory['related_investigations'].add(str(exact['investigation_id']))
                        continue  # Skip semantic if exact match found

                    # PASS 2: Semantic search via pgvector (lower confidence, clearly labeled)
                    similar = await self._semantic_search(cur, etype, evalue)
                    if similar:
                        memory['similar_entities'].append({
                            'entity': evalue,
                            'similar_to': similar['entity_value'],
                            'type': etype,
                            'conclusion': similar['verdict'],
                            'confidence': float(similar['confidence'] or 0) * 0.8,
                            'investigation_id': str(similar['investigation_id']),
                            'distance': float(similar['distance']),
                            'match_type': 'similar'
                        })
                        memory['related_investigations'].add(str(similar['investigation_id']))

                        logger.info(
                            f"Semantic match: {evalue} ~ {similar['entity_value']} "
                            f"(type={etype}, dist={similar['distance']:.4f}, "
                            f"threshold={self._get_threshold(etype)})"
                        )
        finally:
            conn.close()

        # Convert set to list for JSON serialization
        memory['related_investigations'] = list(memory['related_investigations'])
        return memory

    def _exact_match(self, cur, entity_type, entity_value):
        """
        Exact value match — NO normalization.
        Joins entity_observations -> investigations to get verdict + confidence.
        """
        cur.execute("""
            SELECT
                e.value as entity_value,
                e.entity_type as entity_type,
                eo.investigation_id,
                eo.observed_at,
                i.verdict,
                i.confidence
            FROM entities e
            JOIN entity_observations eo ON eo.entity_id = e.id
            JOIN investigations i ON i.id = eo.investigation_id
            WHERE e.type = %s
              AND e.value = %s
              AND i.verdict IS NOT NULL
            ORDER BY eo.created_at DESC
            LIMIT 1
        """, (entity_type, entity_value))
        row = cur.fetchone()
        return dict(row) if row else None

    async def _semantic_search(self, cur, entity_type, entity_value):
        """
        pgvector cosine distance search with per-type threshold.
        """
        embedding = await self._get_embedding(entity_value)
        if embedding is None:
            return None

        threshold = self._get_threshold(entity_type)

        cur.execute("""
            SELECT
                e.value as entity_value,
                e.entity_type as entity_type,
                eo.investigation_id,
                eo.observed_at,
                i.verdict,
                i.confidence,
                e.embedding <-> %s::vector as distance
            FROM entities e
            JOIN entity_observations eo ON eo.entity_id = e.id
            JOIN investigations i ON i.id = eo.investigation_id
            WHERE e.type = %s
              AND e.value != %s
              AND e.embedding IS NOT NULL
              AND e.embedding <-> %s::vector < %s
              AND i.verdict IS NOT NULL
            ORDER BY e.embedding <-> %s::vector
            LIMIT 1
        """, (str(embedding), entity_type, entity_value, str(embedding), threshold, str(embedding)))
        row = cur.fetchone()
        return dict(row) if row else None

    async def _get_embedding(self, text):
        """Get embedding via LiteLLM embed endpoint."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    self.embed_url,
                    json={"inputs": text}
                )
                resp.raise_for_status()
                embeddings = resp.json()
                return embeddings[0] if embeddings else None
        except Exception as e:
            logger.warning(f"Embedding request failed for '{text}': {e}")
            return None

    def _get_threshold(self, entity_type):
        """Get similarity threshold — env override or per-type default."""
        if SIMILARITY_OVERRIDE > 0:
            return SIMILARITY_OVERRIDE
        return SIMILARITY_THRESHOLDS.get(entity_type, 0.20)
