"""Nightly cipher audit processing workflow.

Temporal cron schedule: 0 3 * * * (daily at 3 AM UTC)

Performs scheduled maintenance for the cipher audit subsystem:
1. Refreshes the cipher_audit_summary materialized view
2. Flags newly critical findings (protocol downgrades, expired certs)
3. Computes per-server trend metrics (rolling 7-day window)
4. Emits summary stats for monitoring
"""
import logging
from datetime import timedelta

from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    from database.pool_manager import pooled_connection

logger = logging.getLogger(__name__)


@activity.defn
async def refresh_cipher_audit_summary(params: dict) -> dict:
    """Refresh the cipher_audit_summary materialized view.

    Returns: {refreshed: bool, error: str|None}
    """
    try:
        with pooled_connection("background") as conn:
            with conn.cursor() as cur:
                cur.execute("REFRESH MATERIALIZED VIEW cipher_audit_summary")
        return {"refreshed": True, "error": None}
    except Exception as e:
        logger.warning(f"Failed to refresh cipher_audit_summary: {e}")
        return {"refreshed": False, "error": str(e)}


@activity.defn
async def flag_new_critical_ciphers(params: dict) -> dict:
    """Identify cipher audit events from the last 24h that are critical
    and have not yet been flagged (llm_headline IS NULL).

    Stamps a deterministic headline so dashboards can display it immediately
    without waiting for LLM enrichment.

    Returns: {flagged: int}
    """
    tenant_id = params.get("tenant_id")
    flagged = 0

    try:
        with pooled_connection("normal") as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE cipher_audit_events
                    SET llm_headline = CASE
                        WHEN vulnerability_class = 'deprecated_protocol'
                            THEN 'Deprecated TLS protocol ' || ssl_protocol || ' in use on ' || server_hostname
                        WHEN vulnerability_class = 'broken_cipher'
                            THEN 'Broken cipher suite ' || ssl_cipher || ' detected on ' || server_hostname
                        WHEN vulnerability_class = 'insufficient_key_length'
                            THEN 'Insufficient key length (' || COALESCE(security_bits::text, '?') || ' bits) on ' || server_hostname
                        ELSE 'Critical cipher finding on ' || server_hostname
                    END
                    WHERE tenant_id = COALESCE(%s::uuid, tenant_id)
                      AND risk_level = 'critical'
                      AND llm_headline IS NULL
                      AND observed_at >= NOW() - INTERVAL '24 hours'
                """, (tenant_id,))
                flagged = cur.rowcount
    except Exception as e:
        logger.warning(f"Failed to flag critical ciphers: {e}")

    return {"flagged": flagged}


@activity.defn
async def compute_cipher_trend_metrics(params: dict) -> dict:
    """Compute rolling 7-day cipher health metrics per tenant.

    Returns: {
        tenants_scanned: int,
        total_critical: int,
        total_warning: int,
        total_secure: int,
        worst_servers: [{server, critical_count}],
    }
    """
    total_critical = 0
    total_warning = 0
    total_secure = 0
    tenants_scanned = 0
    worst_servers = []

    try:
        with pooled_connection("background") as conn:
            with conn.cursor() as cur:
                # Aggregate across all tenants for the last 7 days
                cur.execute("""
                    SELECT
                        COUNT(*) FILTER (WHERE risk_level = 'critical') AS critical,
                        COUNT(*) FILTER (WHERE risk_level = 'warning') AS warning,
                        COUNT(*) FILTER (WHERE risk_level = 'secure') AS secure,
                        COUNT(DISTINCT tenant_id) AS tenants
                    FROM cipher_audit_events
                    WHERE observed_at >= NOW() - INTERVAL '7 days'
                """)
                row = cur.fetchone()
                if row:
                    total_critical = row[0] or 0
                    total_warning = row[1] or 0
                    total_secure = row[2] or 0
                    tenants_scanned = row[3] or 0

                # Top 10 worst servers by critical count (7-day window)
                cur.execute("""
                    SELECT server_hostname,
                           COUNT(*) FILTER (WHERE risk_level = 'critical') AS crit
                    FROM cipher_audit_events
                    WHERE observed_at >= NOW() - INTERVAL '7 days'
                      AND risk_level = 'critical'
                    GROUP BY server_hostname
                    ORDER BY crit DESC
                    LIMIT 10
                """)
                for row in cur.fetchall():
                    worst_servers.append({
                        "server": row[0],
                        "critical_count": row[1],
                    })
    except Exception as e:
        logger.warning(f"Failed to compute cipher trend metrics: {e}")

    return {
        "tenants_scanned": tenants_scanned,
        "total_critical": total_critical,
        "total_warning": total_warning,
        "total_secure": total_secure,
        "worst_servers": worst_servers,
    }


@workflow.defn
class CipherAuditCronWorkflow:
    """Nightly cipher audit processing.

    Intended to be scheduled as a Temporal cron workflow:
        tctl schedule create \\
            --schedule-id cipher-audit-nightly \\
            --cron '0 3 * * *' \\
            --workflow-type CipherAuditCronWorkflow \\
            --task-queue zovarc-tasks \\
            --input '{}'

    Stages:
        1. Refresh materialized view (cipher_audit_summary)
        2. Flag new critical findings with deterministic headlines
        3. Compute rolling 7-day trend metrics
    """

    @workflow.run
    async def run(self, params: dict) -> dict:
        tenant_id = params.get("tenant_id")  # None = all tenants

        # Stage 1: Refresh materialized view
        refresh_result = await workflow.execute_activity(
            refresh_cipher_audit_summary,
            {"tenant_id": tenant_id},
            start_to_close_timeout=timedelta(minutes=5),
        )

        # Stage 2: Flag new critical findings
        flag_result = await workflow.execute_activity(
            flag_new_critical_ciphers,
            {"tenant_id": tenant_id},
            start_to_close_timeout=timedelta(minutes=5),
        )

        # Stage 3: Compute trend metrics
        trend_result = await workflow.execute_activity(
            compute_cipher_trend_metrics,
            {"tenant_id": tenant_id},
            start_to_close_timeout=timedelta(minutes=5),
        )

        return {
            "refresh": refresh_result,
            "flagged_critical": flag_result.get("flagged", 0),
            "trends": trend_result,
        }
