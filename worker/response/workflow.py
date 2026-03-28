"""Response playbook workflow — executes SOAR playbooks with approval gates."""

import os
import json
from datetime import timedelta
from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    from response.actions import get_action


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


@activity.defn
async def load_playbook(data: dict) -> dict:
    """Load a playbook from the database."""
    playbook_id = data.get("playbook_id")
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM response_playbooks WHERE id = %s", (playbook_id,))
            row = cur.fetchone()
            if row:
                result = dict(row)
                result["id"] = str(result["id"])
                if result.get("tenant_id"):
                    result["tenant_id"] = str(result["tenant_id"])
                return result
            return {}
    finally:
        conn.close()


@activity.defn
async def create_response_execution(data: dict) -> str:
    """Create a response_executions record. Returns execution_id."""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO response_executions
                (playbook_id, investigation_id, tenant_id, trigger_data, status)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                data.get("playbook_id"),
                data.get("investigation_id"),
                data.get("tenant_id"),
                json.dumps(data.get("trigger_data", {})),
                data.get("status", "pending"),
            ))
            row = cur.fetchone()
            execution_id = str(row[0]) if row else None
        conn.commit()
        return execution_id
    finally:
        conn.close()


@activity.defn
async def update_response_execution(data: dict) -> None:
    """Update response_executions status and actions."""
    execution_id = data.get("execution_id")
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            updates = []
            params = []
            if "status" in data:
                updates.append("status = %s")
                params.append(data["status"])
            if "actions_executed" in data:
                updates.append("actions_executed = %s")
                params.append(json.dumps(data["actions_executed"]))
            if data.get("status") in ("completed", "failed", "rolled_back"):
                updates.append("completed_at = NOW()")
            if updates:
                params.append(execution_id)
                cur.execute(
                    f"UPDATE response_executions SET {', '.join(updates)} WHERE id = %s",
                    params
                )
        conn.commit()
    finally:
        conn.close()


@activity.defn
async def execute_response_action(data: dict) -> dict:
    """Execute a single response action with template variable resolution."""
    action_type = data.get("action_type", "unknown")
    context = data.get("context", {})

    # Resolve template variables ({{attacker_ip}} → actual IPs) before execution
    investigation_id = context.get("investigation_id")
    tenant_id = context.get("tenant_id")
    if investigation_id and tenant_id:
        try:
            from response.template_resolver import PlaybookTemplateResolver, fetch_investigation_data
            inv_data = fetch_investigation_data(investigation_id, tenant_id)
            resolver = PlaybookTemplateResolver()
            context = resolver.resolve_action_context(context, inv_data)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Template resolution failed (non-fatal): {e}")

    action = get_action(action_type)
    if not action.validate(context):
        return {"status": "skipped", "action": action_type, "reason": "validation failed"}

    try:
        result = await action.execute(context)
        return result
    except Exception as e:
        return {"status": "error", "action": action_type, "error": str(e)}


@activity.defn
async def rollback_response_action(data: dict) -> dict:
    """Rollback a single response action."""
    action_type = data.get("action_type", "unknown")
    context = data.get("context", {})
    execution_result = data.get("execution_result", {})

    action = get_action(action_type)
    try:
        result = await action.rollback(context, execution_result)
        return result
    except Exception as e:
        return {"status": "rollback_error", "action": action_type, "error": str(e)}


@activity.defn
async def find_matching_playbooks(data: dict) -> list:
    """Find playbooks matching trigger conditions for an investigation result."""
    verdict = data.get("verdict", "")
    risk_score = data.get("risk_score", 0)
    tenant_id = data.get("tenant_id")

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Match playbooks where verdict matches and risk_score >= threshold
            cur.execute("""
                SELECT id::text, name, trigger_conditions, actions, requires_approval
                FROM response_playbooks
                WHERE enabled = true
                  AND (tenant_id = %s OR tenant_id IS NULL)
                ORDER BY tenant_id NULLS LAST
            """, (tenant_id,))
            playbooks = []
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
                if risk_score < risk_gte:
                    continue
                playbooks.append(dict(row))
            return playbooks
    finally:
        conn.close()


@workflow.defn
class ResponsePlaybookWorkflow:
    """Execute a response playbook with approval gates and rollback."""

    _approval_decision = None

    @workflow.signal
    async def playbook_approval_decision(self, data: dict):
        self._approval_decision = data

    @workflow.run
    async def run(self, params: dict) -> dict:
        playbook_id = params.get("playbook_id")
        investigation_id = params.get("investigation_id")
        tenant_id = params.get("tenant_id")
        trigger_data = params.get("trigger_data", {})

        # 1. Load playbook
        playbook = await workflow.execute_activity(
            load_playbook,
            {"playbook_id": playbook_id},
            schedule_to_close_timeout=timedelta(seconds=10),
        )

        if not playbook:
            return {"status": "error", "message": "Playbook not found"}

        # 2. Create execution record
        execution_id = await workflow.execute_activity(
            create_response_execution,
            {
                "playbook_id": playbook_id,
                "investigation_id": investigation_id,
                "tenant_id": tenant_id,
                "trigger_data": trigger_data,
                "status": "pending",
            },
            schedule_to_close_timeout=timedelta(seconds=10),
        )

        # 3. Approval gate (if required)
        if playbook.get("requires_approval", True):
            await workflow.execute_activity(
                update_response_execution,
                {"execution_id": execution_id, "status": "awaiting_approval"},
                schedule_to_close_timeout=timedelta(seconds=10),
            )

            workflow.logger.info(f"Playbook '{playbook['name']}' awaiting approval")

            # Wait for approval signal (timeout after 1 hour)
            try:
                await workflow.wait_condition(
                    lambda: self._approval_decision is not None,
                    timeout=timedelta(hours=1),
                )
            except TimeoutError:
                await workflow.execute_activity(
                    update_response_execution,
                    {"execution_id": execution_id, "status": "cancelled"},
                    schedule_to_close_timeout=timedelta(seconds=10),
                )
                return {"status": "cancelled", "reason": "approval_timeout"}

            if not self._approval_decision.get("approved", False):
                await workflow.execute_activity(
                    update_response_execution,
                    {"execution_id": execution_id, "status": "cancelled"},
                    schedule_to_close_timeout=timedelta(seconds=10),
                )
                return {"status": "cancelled", "reason": "approval_denied"}

        # 4. Execute actions sequentially
        await workflow.execute_activity(
            update_response_execution,
            {"execution_id": execution_id, "status": "executing"},
            schedule_to_close_timeout=timedelta(seconds=10),
        )

        actions = playbook.get("actions", [])
        if isinstance(actions, str):
            actions = json.loads(actions)

        executed_actions = []
        failed = False

        for action_def in actions:
            action_type = action_def.get("type", "unknown")
            context = action_def.get("context", {})
            context["tenant_id"] = tenant_id
            context["investigation_id"] = investigation_id

            result = await workflow.execute_activity(
                execute_response_action,
                {"action_type": action_type, "context": context},
                schedule_to_close_timeout=timedelta(seconds=30),
            )

            executed_actions.append({
                "action_type": action_type,
                "context": context,
                "result": result,
            })

            if result.get("status") == "error":
                failed = True
                workflow.logger.info(f"Action {action_type} failed: {result.get('error')}")
                break

        # 5. If failed, rollback completed actions
        if failed:
            for ea in reversed(executed_actions[:-1]):  # Skip the failed one
                await workflow.execute_activity(
                    rollback_response_action,
                    {
                        "action_type": ea["action_type"],
                        "context": ea["context"],
                        "execution_result": ea["result"],
                    },
                    schedule_to_close_timeout=timedelta(seconds=30),
                )

            final_status = "rolled_back"
        else:
            final_status = "completed"

        # 6. Update final status
        await workflow.execute_activity(
            update_response_execution,
            {
                "execution_id": execution_id,
                "status": final_status,
                "actions_executed": executed_actions,
            },
            schedule_to_close_timeout=timedelta(seconds=10),
        )

        workflow.logger.info(f"Playbook '{playbook['name']}' {final_status}: {len(executed_actions)} actions")
        return {
            "status": final_status,
            "execution_id": execution_id,
            "actions_executed": len(executed_actions),
            "playbook_name": playbook.get("name"),
        }
