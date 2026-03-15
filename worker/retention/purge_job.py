"""Data retention enforcement — purges expired data per tenant policies (Security P2#25)."""
import os
import psycopg2
from temporalio import activity

import logger


DEFAULT_RETENTION_DAYS = {
    "investigations": 365,
    "audit_events": 730,
    "llm_call_log": 90,
    "siem_alerts": 180,
    "investigation_cache": 30,
}

PURGE_QUERIES = {
    "investigations": (
        "DELETE FROM investigations WHERE tenant_id = %s "
        "AND created_at < NOW() - make_interval(days => %s) "
        "AND status IN ('completed','blocked','cancelled')"
    ),
    "audit_events": (
        "DELETE FROM audit_events WHERE tenant_id = %s "
        "AND created_at < NOW() - make_interval(days => %s)"
    ),
    "llm_call_log": (
        "DELETE FROM llm_call_log WHERE tenant_id = %s "
        "AND created_at < NOW() - make_interval(days => %s)"
    ),
    "siem_alerts": (
        "DELETE FROM siem_alerts WHERE tenant_id = %s "
        "AND created_at < NOW() - make_interval(days => %s) "
        "AND status IN ('resolved','dismissed')"
    ),
    "investigation_cache": (
        "DELETE FROM investigation_cache WHERE tenant_id = %s "
        "AND created_at < NOW() - make_interval(days => %s)"
    ),
}


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


@activity.defn
async def enforce_retention(params: dict) -> dict:
    """Enforce data retention policies for a tenant.

    Args:
        params: {tenant_id, policies (optional dict of table->days)}
    Returns:
        {tenant_id, tables_purged, total_deleted}
    """
    tenant_id = params.get("tenant_id")
    policies = params.get("policies", DEFAULT_RETENTION_DAYS)

    total_deleted = 0
    tables_purged = {}

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            for table, query in PURGE_QUERIES.items():
                days = policies.get(table, DEFAULT_RETENTION_DAYS.get(table, 365))
                cur.execute(query, (tenant_id, days))
                deleted = cur.rowcount
                if deleted > 0:
                    tables_purged[table] = deleted
                    total_deleted += deleted
                    logger.info("retention_purged",
                                tenant_id=tenant_id, table=table, deleted=deleted)
        conn.commit()
    finally:
        conn.close()

    return {
        "tenant_id": tenant_id,
        "tables_purged": tables_purged,
        "total_deleted": total_deleted,
    }


@activity.defn
async def enforce_all_tenant_retention(params: dict) -> dict:
    """Run retention enforcement for all active tenants.

    Args:
        params: {} (no params needed)
    Returns:
        {tenants_processed, total_deleted}
    """
    conn = _get_db()
    tenant_ids = []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM tenants WHERE is_active = true")
            tenant_ids = [str(row[0]) for row in cur.fetchall()]
    finally:
        conn.close()

    total_deleted = 0
    for tid in tenant_ids:
        # Load tenant-specific policies if defined
        policies = dict(DEFAULT_RETENTION_DAYS)
        try:
            conn = _get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT table_name, retention_days FROM data_retention_policies "
                        "WHERE tenant_id = %s AND is_active = true",
                        (tid,)
                    )
                    for row in cur.fetchall():
                        policies[row[0]] = row[1]
            finally:
                conn.close()
        except Exception:
            pass

        result = await enforce_retention({"tenant_id": tid, "policies": policies})
        total_deleted += result.get("total_deleted", 0)

    logger.info("retention_sweep_complete",
                tenants_processed=len(tenant_ids), total_deleted=total_deleted)

    return {
        "tenants_processed": len(tenant_ids),
        "total_deleted": total_deleted,
    }
