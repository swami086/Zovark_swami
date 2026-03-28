"""Investigation SLA monitoring activity (Issue #54).

Checks agent_tasks for overdue investigations based on severity-based SLA thresholds.
Fires webhooks for SLA breaches and records events to sla_events table.
"""

import os
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


# SLA thresholds in minutes by severity
SLA_THRESHOLDS = {
    "critical": 15,
    "high": 30,
    "medium": 120,
    "low": 480,
}


@activity.defn
async def check_sla_compliance(data: dict) -> dict:
    """Check SLA compliance for in-progress investigations.

    Input: {tenant_id: optional, webhook_url: optional}
    Returns: {
        checked: int, breached: int, compliant: int,
        breaches: [{task_id, severity, threshold_min, actual_min, breach_ratio}]
    }
    """
    tenant_id = data.get("tenant_id")
    webhook_url = data.get("webhook_url", os.environ.get("SLA_WEBHOOK_URL", ""))

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Find in-progress tasks with severity
            query = """
                SELECT id::text, tenant_id::text, status, severity,
                       created_at,
                       EXTRACT(EPOCH FROM (NOW() - created_at)) / 60.0 as elapsed_minutes
                FROM agent_tasks
                WHERE status IN ('pending', 'executing', 'awaiting_approval')
            """
            params = []
            if tenant_id:
                query += " AND tenant_id = %s"
                params.append(tenant_id)

            cur.execute(query, params)
            tasks = [dict(r) for r in cur.fetchall()]

        checked = 0
        breached = 0
        compliant = 0
        breaches = []

        for task in tasks:
            severity = task.get("severity", "medium")
            if severity not in SLA_THRESHOLDS:
                severity = "medium"

            threshold = SLA_THRESHOLDS[severity]
            elapsed = float(task.get("elapsed_minutes", 0))
            task_id = task["id"]
            task_tenant_id = task["tenant_id"]

            checked += 1

            if elapsed > threshold:
                breached += 1
                breach_ratio = round(elapsed / threshold, 2)

                breach_info = {
                    "task_id": task_id,
                    "tenant_id": task_tenant_id,
                    "severity": severity,
                    "threshold_minutes": threshold,
                    "actual_minutes": round(elapsed, 1),
                    "breach_ratio": breach_ratio,
                    "status": task.get("status"),
                }
                breaches.append(breach_info)

                # Record SLA event
                _record_sla_event(task_tenant_id, task_id, severity,
                                  threshold, elapsed, True, breach_ratio,
                                  webhook_url)

                # Fire webhook for breach
                if webhook_url:
                    _fire_webhook(webhook_url, breach_info)
            else:
                compliant += 1

        return {
            "checked": checked,
            "breached": breached,
            "compliant": compliant,
            "breaches": breaches,
        }

    finally:
        conn.close()


def _record_sla_event(tenant_id, task_id, severity, threshold, actual, breached, breach_ratio, webhook_url):
    """Record SLA event to database."""
    try:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO sla_events
                    (tenant_id, task_id, severity, sla_threshold_minutes,
                     actual_duration_minutes, breached, breach_ratio,
                     webhook_sent, webhook_status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    tenant_id, task_id, severity, threshold,
                    actual, breached, breach_ratio,
                    bool(webhook_url), None,
                ))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"sla_monitor: failed to record event (non-fatal): {e}")


def _fire_webhook(webhook_url, breach_info):
    """Fire webhook for SLA breach. Best-effort, non-blocking."""
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                webhook_url,
                json={
                    "event": "sla_breach",
                    "data": breach_info,
                },
                headers={"Content-Type": "application/json"},
            )
            return resp.status_code
    except Exception as e:
        print(f"sla_monitor: webhook failed (non-fatal): {e}")
        return None
