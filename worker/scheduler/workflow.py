"""Scheduled workflow execution — Temporal cron workflow (Issue #52).

Reads schedule config from DB table `scheduled_workflows` and dispatches
child workflows: DetectionGenerationWorkflow, SelfHealingWorkflow, CrossTenantRefreshWorkflow.
"""

import os
from datetime import timedelta
from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    import psycopg2
    from psycopg2.extras import RealDictCursor


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
    return psycopg2.connect(db_url)


@activity.defn
async def load_scheduled_workflows(data: dict) -> list:
    """Load active scheduled workflow configurations from DB.

    Returns list of {id, workflow_type, cron_expression, params, last_run_at}.
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id::text, workflow_type, cron_expression,
                       params, last_run_at
                FROM scheduled_workflows
                WHERE is_active = true
                ORDER BY workflow_type
            """)
            rows = [dict(r) for r in cur.fetchall()]
            # Convert datetimes to strings for serialization
            for row in rows:
                if row.get("last_run_at"):
                    row["last_run_at"] = str(row["last_run_at"])
            return rows
    finally:
        conn.close()


@activity.defn
async def update_schedule_last_run(data: dict) -> dict:
    """Update the last_run_at timestamp for a scheduled workflow.

    Input: {schedule_id: str}
    Returns: {updated: bool}
    """
    schedule_id = data.get("schedule_id")
    if not schedule_id:
        return {"updated": False}

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE scheduled_workflows
                SET last_run_at = NOW(), updated_at = NOW()
                WHERE id = %s
            """, (schedule_id,))
        conn.commit()
        return {"updated": True}
    finally:
        conn.close()


@workflow.defn
class ScheduledWorkflow:
    """Temporal cron workflow that dispatches scheduled child workflows.

    This workflow is designed to be started with a Temporal cron schedule.
    Each execution loads active schedules from DB and dispatches matching workflows.
    """

    @workflow.run
    async def run(self, params: dict) -> dict:
        workflow_filter = params.get("workflow_type")  # optional: run only specific type

        # 1. Load active schedules from DB
        schedules = await workflow.execute_activity(
            load_scheduled_workflows,
            {},
            schedule_to_close_timeout=timedelta(seconds=30),
        )

        dispatched = 0
        errors = 0
        results = []

        for schedule in schedules:
            wf_type = schedule.get("workflow_type", "")
            schedule_id = schedule.get("id")
            wf_params = schedule.get("params", {})

            # Filter if specific type requested
            if workflow_filter and wf_type != workflow_filter:
                continue

            try:
                # Dispatch the appropriate child workflow
                if wf_type == "DetectionGenerationWorkflow":
                    from detection.workflow import DetectionGenerationWorkflow
                    child_result = await workflow.execute_child_workflow(
                        DetectionGenerationWorkflow.run,
                        wf_params,
                        id=f"scheduled-detection-{schedule_id}",
                        task_queue="zovarc-tasks",
                    )
                elif wf_type == "SelfHealingWorkflow":
                    from sre.workflow import SelfHealingWorkflow
                    child_result = await workflow.execute_child_workflow(
                        SelfHealingWorkflow.run,
                        wf_params,
                        id=f"scheduled-sre-{schedule_id}",
                        task_queue="zovarc-tasks",
                    )
                elif wf_type == "CrossTenantRefreshWorkflow":
                    from intelligence.cross_tenant_workflow import CrossTenantRefreshWorkflow
                    child_result = await workflow.execute_child_workflow(
                        CrossTenantRefreshWorkflow.run,
                        wf_params,
                        id=f"scheduled-cross-tenant-{schedule_id}",
                        task_queue="zovarc-tasks",
                    )
                else:
                    workflow.logger.info(f"Unknown scheduled workflow type: {wf_type}")
                    errors += 1
                    results.append({"workflow_type": wf_type, "status": "unknown_type"})
                    continue

                # Update last_run_at
                await workflow.execute_activity(
                    update_schedule_last_run,
                    {"schedule_id": schedule_id},
                    schedule_to_close_timeout=timedelta(seconds=10),
                )

                dispatched += 1
                results.append({
                    "workflow_type": wf_type,
                    "schedule_id": schedule_id,
                    "status": "dispatched",
                    "result": child_result,
                })
                workflow.logger.info(f"Scheduled workflow dispatched: {wf_type}")

            except Exception as e:
                errors += 1
                results.append({
                    "workflow_type": wf_type,
                    "status": "error",
                    "error": str(e)[:200],
                })
                workflow.logger.info(f"Scheduled workflow {wf_type} failed: {e}")

        return {
            "status": "completed",
            "schedules_loaded": len(schedules),
            "dispatched": dispatched,
            "errors": errors,
            "results": results,
        }
