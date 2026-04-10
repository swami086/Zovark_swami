"""Context loaders — correlation history and institutional knowledge from DB.

Single source of truth — imported by analyze.py and execute.py.
Uses pooled connections via database.pool_manager.pooled_connection().
"""
import logging

from psycopg2.extras import RealDictCursor

_logger = logging.getLogger(__name__)


def _pooled_connection(tier: str = "normal"):
    """Return the pool_manager context manager (or a direct-connect fallback)."""
    from database.pool_manager import pooled_connection
    return pooled_connection(tier)


def load_correlation_context(tenant_id: str, siem_event: dict) -> dict:
    """Load recent investigations with overlapping IOCs for correlation."""
    context = {"investigations": [], "tenant_id": tenant_id}
    try:
        entities = []
        for field_name in ("source_ip", "username", "hostname", "dest_ip"):
            val = siem_event.get(field_name)
            if val:
                entities.append(val)
        if not entities:
            return context

        with _pooled_connection("normal") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(f"SET LOCAL app.current_tenant = '{tenant_id}'")
                cur.execute(
                    "SELECT task_type, (output->>'risk_score')::int as risk_score, "
                    "output->>'verdict' as verdict, input->'siem_event'->>'source_ip' as source_ip, "
                    "created_at::text as timestamp "
                    "FROM agent_tasks "
                    "WHERE tenant_id = %s AND status = 'completed' "
                    "AND created_at > NOW() - INTERVAL '24 hours' "
                    "AND (input->'siem_event'->>'source_ip' = ANY(%s) "
                    "     OR input->'siem_event'->>'username' = ANY(%s)) "
                    "ORDER BY created_at DESC LIMIT 20",
                    (tenant_id, entities, entities),
                )
                for row in cur.fetchall():
                    context["investigations"].append(dict(row))
    except Exception as e:
        _logger.warning("Failed to load correlation context: %s", e)
    return context


def load_institutional_knowledge(tenant_id: str, siem_event: dict) -> dict:
    """Load institutional knowledge for entities in the siem_event."""
    knowledge = {}
    try:
        entities = []
        for field_name in ("source_ip", "username", "hostname", "dest_ip"):
            val = siem_event.get(field_name)
            if val:
                entities.append(val)
        if not entities:
            return knowledge

        with _pooled_connection("normal") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(f"SET LOCAL app.current_tenant = '{tenant_id}'")
                cur.execute(
                    "SELECT entity_value, description, expected_behavior, hours_active, analyst_notes "
                    "FROM institutional_knowledge WHERE tenant_id = %s AND entity_value = ANY(%s)",
                    (tenant_id, entities),
                )
                for row in cur.fetchall():
                    knowledge[row["entity_value"]] = {
                        "description": row.get("description", ""),
                        "expected_behavior": row.get("expected_behavior", ""),
                        "hours_active": row.get("hours_active", ""),
                        "analyst_notes": row.get("analyst_notes", ""),
                    }
    except Exception as e:
        _logger.warning("Failed to load institutional knowledge: %s", e)
    if knowledge:
        _logger.info("Institutional knowledge: found %d known entities", len(knowledge))
    return knowledge
