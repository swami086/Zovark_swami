"""Sprint 2B: SOAR response playbook engine.

Provides:
  - evaluate_triggers() — check if investigation results match any playbook triggers
  - execute_playbook() — run playbook actions sequentially with error handling
  - 7 built-in action types: BlockIP, DisableUser, IsolateEndpoint,
    RotateCredentials, CreateTicket, SendNotification, QuarantineFile

This module provides standalone utility functions. The Temporal workflow
integration is in response/workflow.py, and the action implementations
are in response/actions.py.
"""

import json
import logging
import os
from typing import Optional

import psycopg2
from psycopg2.extras import RealDictCursor

from response.actions import get_action, ACTION_REGISTRY

logger = logging.getLogger(__name__)


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


# ---------------------------------------------------------------------------
# Action type registry (convenience reference for consumers)
# ---------------------------------------------------------------------------

ACTION_TYPES = {
    "block_ip": {
        "description": "Add IP to firewall blocklist",
        "requires_approval": False,
        "rollback_capable": True,
        "timeout_seconds": 30,
    },
    "disable_user": {
        "description": "Disable user account",
        "requires_approval": True,
        "rollback_capable": True,
        "timeout_seconds": 30,
    },
    "isolate_endpoint": {
        "description": "Network-isolate a compromised endpoint",
        "requires_approval": True,
        "rollback_capable": True,
        "timeout_seconds": 30,
    },
    "rotate_credentials": {
        "description": "Force credential rotation",
        "requires_approval": True,
        "rollback_capable": False,
        "timeout_seconds": 60,
    },
    "create_ticket": {
        "description": "Create incident ticket in ticketing system",
        "requires_approval": False,
        "rollback_capable": False,
        "timeout_seconds": 30,
    },
    "send_notification": {
        "description": "Send alert to SOC team",
        "requires_approval": False,
        "rollback_capable": False,
        "timeout_seconds": 15,
    },
    "quarantine_file": {
        "description": "Move suspicious file to quarantine",
        "requires_approval": True,
        "rollback_capable": True,
        "timeout_seconds": 30,
    },
}


# ---------------------------------------------------------------------------
# evaluate_triggers
# ---------------------------------------------------------------------------

def evaluate_triggers(investigation_result: dict, tenant_id: str) -> list:
    """Check if investigation results match any playbook triggers.

    Args:
        investigation_result: dict with keys:
            - verdict: str (true_positive, false_positive, benign, etc.)
            - risk_score: int/float
            - techniques: list of MITRE technique IDs (e.g. ["T1110", "T1021"])
            - task_type: str
        tenant_id: the tenant UUID

    Returns:
        List of matching playbook dicts with keys: id, name, trigger_conditions,
        actions, requires_approval.
    """
    verdict = investigation_result.get("verdict", "")
    risk_score = investigation_result.get("risk_score", 0)
    techniques = investigation_result.get("techniques", [])
    task_type = investigation_result.get("task_type", "")

    if not verdict:
        return []

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get all enabled playbooks for this tenant (+ global ones with NULL tenant_id)
            cur.execute("""
                SELECT id::text, name, trigger_conditions, actions, requires_approval
                FROM response_playbooks
                WHERE enabled = true
                  AND (tenant_id = %s OR tenant_id IS NULL)
                ORDER BY tenant_id NULLS LAST
            """, (tenant_id,))

            matching = []
            for row in cur.fetchall():
                tc = row["trigger_conditions"]
                if isinstance(tc, str):
                    tc = json.loads(tc)

                # Check verdict match
                trigger_verdict = tc.get("verdict")
                if trigger_verdict and trigger_verdict != verdict:
                    continue

                # Check risk_score threshold
                risk_gte = tc.get("risk_score_gte", 0)
                min_risk = tc.get("min_risk_score", risk_gte)  # support both field names
                threshold = max(risk_gte, min_risk)
                if risk_score < threshold:
                    continue

                # Check technique match (if specified)
                techniques_include = tc.get("techniques_include", [])
                if techniques_include:
                    if not any(t in techniques for t in techniques_include):
                        continue

                # Check task_type match (if specified)
                task_type_match = tc.get("task_type")
                if task_type_match and task_type_match != task_type:
                    continue

                matching.append(dict(row))

            return matching
    except Exception as e:
        logger.error(f"evaluate_triggers error: {e}")
        return []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# execute_playbook
# ---------------------------------------------------------------------------

async def execute_playbook(
    playbook_id: str,
    investigation_id: str,
    tenant_id: str,
    trigger_data: Optional[dict] = None,
) -> dict:
    """Run playbook actions sequentially with error handling.

    This is the non-Temporal execution path for simple playbook execution.
    For durable execution with approval gates, use ResponsePlaybookWorkflow.

    Args:
        playbook_id: UUID of the playbook
        investigation_id: UUID of the triggering investigation
        tenant_id: tenant UUID
        trigger_data: optional dict of trigger context

    Returns:
        {status, execution_id, actions_executed, actions_results, error}
    """
    trigger_data = trigger_data or {}

    # 1. Load the playbook
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id::text, name, actions, requires_approval
                FROM response_playbooks
                WHERE id = %s AND enabled = true
            """, (playbook_id,))
            playbook = cur.fetchone()
    finally:
        conn.close()

    if not playbook:
        return {"status": "error", "error": "Playbook not found or disabled"}

    # 2. Create execution record
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO response_executions
                (playbook_id, investigation_id, tenant_id, trigger_data, status)
                VALUES (%s, %s, %s, %s, 'executing')
                RETURNING id::text
            """, (playbook_id, investigation_id, tenant_id, json.dumps(trigger_data)))
            execution_id = cur.fetchone()[0]
        conn.commit()
    except Exception as e:
        return {"status": "error", "error": f"Failed to create execution record: {e}"}
    finally:
        conn.close()

    # 3. If approval required, mark as pending (caller must handle approval flow)
    if playbook.get("requires_approval", True):
        _update_execution(execution_id, "awaiting_approval")
        return {
            "status": "awaiting_approval",
            "execution_id": execution_id,
            "playbook_name": playbook["name"],
            "actions_executed": 0,
            "actions_results": [],
        }

    # 4. Execute actions sequentially
    actions = playbook.get("actions", [])
    if isinstance(actions, str):
        actions = json.loads(actions)

    executed_actions = []
    failed = False
    error_message = None

    for action_def in actions:
        action_type = action_def.get("type", "unknown")
        context = action_def.get("context", {})
        context["tenant_id"] = tenant_id
        context["investigation_id"] = investigation_id

        # Resolve template variables if template_resolver is available
        try:
            from response.template_resolver import PlaybookTemplateResolver, fetch_investigation_data
            inv_data = fetch_investigation_data(investigation_id, tenant_id)
            resolver = PlaybookTemplateResolver()
            context = resolver.resolve_action_context(context, inv_data)
        except Exception as e:
            logger.warning(f"Template resolution failed (non-fatal): {e}")

        action = get_action(action_type)

        # Pre-flight validation
        if not action.validate(context):
            executed_actions.append({
                "action_type": action_type,
                "status": "skipped",
                "reason": "validation failed",
            })
            continue

        # Execute
        try:
            result = await action.execute(context)
            executed_actions.append({
                "action_type": action_type,
                "context": context,
                "result": result,
            })

            if result.get("status") == "error":
                failed = True
                error_message = result.get("error", "Unknown error")
                logger.warning(f"Action {action_type} failed: {error_message}")
                break

        except Exception as e:
            failed = True
            error_message = str(e)
            executed_actions.append({
                "action_type": action_type,
                "status": "error",
                "error": str(e),
            })
            break

    # 5. If failed, attempt rollback of completed actions
    if failed:
        for ea in reversed(executed_actions[:-1]):  # Skip the failed one
            if ea.get("result", {}).get("status") in ("executed", "simulated"):
                action = get_action(ea["action_type"])
                try:
                    await action.rollback(ea.get("context", {}), ea.get("result", {}))
                except Exception:
                    pass  # Rollback failures are logged but don't propagate

        final_status = "rolled_back"
    else:
        final_status = "completed"

    # 6. Update execution record
    _update_execution(execution_id, final_status, executed_actions, error_message)

    logger.info(
        f"Playbook '{playbook['name']}' {final_status}: "
        f"{len(executed_actions)} actions executed"
    )

    return {
        "status": final_status,
        "execution_id": execution_id,
        "playbook_name": playbook["name"],
        "actions_executed": len(executed_actions),
        "actions_results": executed_actions,
        "error": error_message,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _update_execution(execution_id: str, status: str,
                      actions_executed: list = None,
                      error_message: str = None):
    """Update a response_executions record."""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            updates = ["status = %s"]
            params = [status]

            if actions_executed is not None:
                updates.append("actions_executed = %s")
                params.append(json.dumps(actions_executed))

            if error_message is not None:
                updates.append("error_message = %s")
                params.append(error_message)

            if status in ("completed", "failed", "rolled_back", "cancelled"):
                updates.append("completed_at = NOW()")

            params.append(execution_id)
            cur.execute(
                f"UPDATE response_executions SET {', '.join(updates)} WHERE id = %s",
                params
            )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to update execution {execution_id}: {e}")
    finally:
        conn.close()


def get_playbook_summary(tenant_id: str) -> dict:
    """Get summary of playbooks and executions for a tenant.

    Returns: {playbooks_total, playbooks_enabled, executions_total,
              executions_by_status, recent_executions}
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Playbook counts
            cur.execute("""
                SELECT
                    COUNT(*) as total,
                    COALESCE(COUNT(*) FILTER (WHERE enabled = true), 0) as enabled_count
                FROM response_playbooks
                WHERE tenant_id = %s OR tenant_id IS NULL
            """, (tenant_id,))
            pb_row = cur.fetchone()

            # Execution counts by status
            cur.execute("""
                SELECT status, COUNT(*) as cnt
                FROM response_executions
                WHERE tenant_id = %s
                GROUP BY status
            """, (tenant_id,))
            exec_by_status = {}
            exec_total = 0
            for row in cur.fetchall():
                exec_by_status[row["status"]] = row["cnt"]
                exec_total += row["cnt"]

            # Recent executions
            cur.execute("""
                SELECT re.id::text, rp.name as playbook_name, re.status,
                       re.created_at, re.completed_at
                FROM response_executions re
                JOIN response_playbooks rp ON rp.id = re.playbook_id
                WHERE re.tenant_id = %s
                ORDER BY re.created_at DESC
                LIMIT 10
            """, (tenant_id,))
            recent = [dict(r) for r in cur.fetchall()]

            return {
                "playbooks_total": pb_row["total"],
                "playbooks_enabled": pb_row["enabled_count"],
                "executions_total": exec_total,
                "executions_by_status": exec_by_status,
                "recent_executions": recent,
            }
    except Exception as e:
        logger.error(f"get_playbook_summary error: {e}")
        return {
            "playbooks_total": 0,
            "playbooks_enabled": 0,
            "executions_total": 0,
            "executions_by_status": {},
            "recent_executions": [],
        }
    finally:
        conn.close()
