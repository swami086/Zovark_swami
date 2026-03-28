"""Blast radius computation — entity graph traversal via recursive CTE."""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


@activity.defn
async def compute_blast_radius(data: dict) -> dict:
    """Traverse entity graph to compute blast radius for an investigation.

    Input: {investigation_id, tenant_id, time_window_hours: 72, max_hops: 2}
    Returns: {investigation_id, affected_entities, affected_investigations, total_entities, max_threat_score, summary}
    """
    investigation_id = data.get("investigation_id")
    tenant_id = data.get("tenant_id")
    time_window_hours = data.get("time_window_hours", 72)
    max_hops = data.get("max_hops", 2)

    if not investigation_id or not tenant_id:
        return {"investigation_id": investigation_id, "affected_entities": [], "affected_investigations": [], "total_entities": 0, "max_threat_score": 0, "summary": "Missing parameters"}

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Recursive CTE for graph traversal
            cur.execute("""
                WITH RECURSIVE blast AS (
                    SELECT DISTINCT e.id as entity_id, e.entity_type, e.value, e.threat_score, 0 as hop
                    FROM entity_observations eo
                    JOIN entities e ON e.id = eo.entity_id
                    WHERE eo.investigation_id = %s

                    UNION

                    SELECT e2.id, e2.entity_type, e2.value, e2.threat_score, b.hop + 1
                    FROM blast b
                    JOIN entity_edges ee ON (ee.source_entity_id = b.entity_id OR ee.target_entity_id = b.entity_id)
                    JOIN entities e2 ON e2.id = CASE
                        WHEN ee.source_entity_id = b.entity_id THEN ee.target_entity_id
                        ELSE ee.source_entity_id
                    END
                    WHERE b.hop < %s
                    AND ee.observed_at > NOW() - make_interval(hours => %s)
                    AND e2.tenant_id = %s
                )
                SELECT DISTINCT ON (entity_id)
                    entity_id::text, entity_type, value, threat_score, MIN(hop) as nearest_hop
                FROM blast
                GROUP BY entity_id, entity_type, value, threat_score
                ORDER BY entity_id, MIN(hop)
            """, (investigation_id, max_hops, time_window_hours, tenant_id))

            affected_entities = [dict(r) for r in cur.fetchall()]

            # Find related investigations that share entities
            entity_ids = [e["entity_id"] for e in affected_entities]
            affected_investigations = []

            if entity_ids:
                cur.execute("""
                    SELECT i.id::text as investigation_id, i.verdict, i.risk_score,
                           COUNT(DISTINCT eo.entity_id) as shared_entities
                    FROM investigations i
                    JOIN entity_observations eo ON eo.investigation_id = i.id
                    WHERE eo.entity_id = ANY(%s::uuid[])
                    AND i.id != %s::uuid
                    AND i.tenant_id = %s
                    GROUP BY i.id, i.verdict, i.risk_score
                    ORDER BY shared_entities DESC
                    LIMIT 20
                """, (entity_ids, investigation_id, tenant_id))
                affected_investigations = [dict(r) for r in cur.fetchall()]

        total_entities = len(affected_entities)
        max_threat_score = max((e.get("threat_score") or 0 for e in affected_entities), default=0)

        summary = (
            f"Impact assessment: {total_entities} entities across {max_hops} hops, "
            f"{len(affected_investigations)} related investigations"
        )

        return {
            "investigation_id": investigation_id,
            "affected_entities": affected_entities,
            "affected_investigations": affected_investigations,
            "total_entities": total_entities,
            "max_threat_score": max_threat_score,
            "summary": summary,
        }

    except Exception as e:
        print(f"compute_blast_radius non-fatal error: {e}")
        return {
            "investigation_id": investigation_id,
            "affected_entities": [],
            "affected_investigations": [],
            "total_entities": 0,
            "max_threat_score": 0,
            "summary": f"Error: {e}",
        }
    finally:
        conn.close()
