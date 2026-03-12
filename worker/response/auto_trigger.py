"""Auto-trigger response playbooks on investigation completion (Issue #51).

After investigation completes with true_positive verdict and high/critical severity,
find matching playbooks and start ResponsePlaybookWorkflow for each.
"""

import os
import json
import psycopg2
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


@activity.defn
async def auto_trigger_playbooks(data: dict) -> dict:
    """Auto-trigger response playbooks after investigation completion.

    Input: {
        investigation_id, tenant_id, verdict, severity, risk_score,
        task_id, task_type, matching_playbooks: [{id, name, ...}]
    }
    Returns: {triggered: int, playbook_ids: [...], skipped_reason: str|None}
    """
    investigation_id = data.get("investigation_id")
    tenant_id = data.get("tenant_id")
    verdict = data.get("verdict", "")
    severity = data.get("severity", "")
    risk_score = data.get("risk_score", 0)
    task_id = data.get("task_id")
    task_type = data.get("task_type")
    matching_playbooks = data.get("matching_playbooks", [])

    # Only auto-trigger for true_positive with high/critical severity
    if verdict != "true_positive" or severity not in ("high", "critical"):
        return {
            "triggered": 0,
            "playbook_ids": [],
            "skipped_reason": f"Auto-trigger skipped: verdict={verdict}, severity={severity}",
        }

    if not matching_playbooks:
        return {
            "triggered": 0,
            "playbook_ids": [],
            "skipped_reason": "No matching playbooks found",
        }

    triggered_ids = []

    # Log each trigger to audit_events
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            for pb in matching_playbooks:
                playbook_id = pb.get("id")
                playbook_name = pb.get("name", "unknown")

                cur.execute("""
                    INSERT INTO audit_events
                    (tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    tenant_id,
                    "playbook_auto_triggered",
                    "system",
                    "investigation",
                    investigation_id,
                    json.dumps({
                        "playbook_id": playbook_id,
                        "playbook_name": playbook_name,
                        "verdict": verdict,
                        "severity": severity,
                        "risk_score": risk_score,
                        "task_id": task_id,
                        "task_type": task_type,
                    }),
                ))
                triggered_ids.append(playbook_id)

        conn.commit()
    except Exception as e:
        print(f"auto_trigger_playbooks: audit log failed (non-fatal): {e}")
    finally:
        conn.close()

    return {
        "triggered": len(triggered_ids),
        "playbook_ids": triggered_ids,
        "skipped_reason": None,
    }
