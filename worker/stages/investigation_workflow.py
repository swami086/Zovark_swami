"""
Investigation Workflow V2 — 5-stage pipeline.

~40 lines vs 1300 in legacy. Runs alongside _legacy_workflows.py.

Stages:
  1. INGEST  (30s)  — dedup, PII mask, skill retrieval
  2. ANALYZE (5min) — template/LLM/stub code generation
  3. EXECUTE (2min) — Docker sandbox execution
  4. ASSESS  (1min) — verdict, summary, FP analysis
  5. STORE   (30s)  — DB writes, memory, patterns
"""
from datetime import timedelta
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from stages.ingest import ingest_alert
    from stages.analyze import analyze_alert
    from stages.execute import execute_investigation
    from stages.assess import assess_results
    from stages.store import store_investigation


@workflow.defn
class InvestigationWorkflowV2:
    """5-stage investigation pipeline. No hidden LLM calls."""

    @workflow.run
    async def run(self, task_data: dict) -> dict:
        # Extract task_id from Temporal workflow ID (same as legacy)
        info = workflow.info()
        task_id = info.workflow_id.replace("task-", "")

        # Fetch full task from DB via legacy fetch_task activity
        # Timeout allows for retry loop (8 retries × ~1-3s each = up to 15s)
        full_task = await workflow.execute_activity(
            "fetch_task", task_id,
            start_to_close_timeout=timedelta(seconds=30),
        )
        if not full_task:
            return {"status": "failed", "task_id": task_id, "error": "Task not found"}

        # Inject task_id and tenant_id into task_data
        full_task["task_id"] = task_id

        # Stage 1: INGEST — dedup, PII mask, skill match (no LLM)
        ingested = await workflow.execute_activity(
            ingest_alert, full_task,
            start_to_close_timeout=timedelta(seconds=30),
        )

        if ingested.get("is_duplicate"):
            return {
                "status": "deduplicated",
                "task_id": ingested["task_id"],
                "duplicate_of": ingested.get("duplicate_of"),
            }

        # Stage 2: ANALYZE — generate investigation code (LLM boundary)
        # 900s timeout: Path C (full LLM gen) takes 120-270s per call on RTX 3050,
        # and the LLM queues requests sequentially on single GPU
        analyzed = await workflow.execute_activity(
            analyze_alert, ingested,
            start_to_close_timeout=timedelta(seconds=900),
        )

        if not analyzed.get("code"):
            return {"status": "failed", "task_id": ingested["task_id"],
                    "error": "Code generation produced no output"}

        # Derive path_taken from analyze output
        path_taken = analyzed.get("path_taken", analyzed.get("source", "unknown"))

        # Stage 3: EXECUTE — sandbox execution (no LLM)
        executed = await workflow.execute_activity(
            execute_investigation,
            {"code": analyzed["code"], "task_type": ingested["task_type"], "source": analyzed.get("source", "")},
            start_to_close_timeout=timedelta(seconds=120),
        )

        # Stage 4: ASSESS — verdict + summary (LLM boundary)
        assessed = await workflow.execute_activity(
            assess_results,
            {
                **executed,
                "task_id": ingested["task_id"],
                "tenant_id": ingested["tenant_id"],
                "task_type": ingested["task_type"],
                "siem_event": ingested.get("siem_event", {}),
                "path_taken": path_taken,
            },
            start_to_close_timeout=timedelta(seconds=60),
        )

        # Extract trace_id from task row (set by Go API at INSERT)
        trace_id = full_task.get("trace_id", "")

        # Stage 5: STORE — persist everything (no LLM)
        # assessed values (verdict, risk_score, recommendations) must take
        # precedence over raw executed values — spread assessed LAST
        stored = await workflow.execute_activity(
            store_investigation,
            {
                **executed,
                **assessed,
                "task_id": ingested["task_id"],
                "tenant_id": ingested["tenant_id"],
                "task_type": ingested["task_type"],
                "siem_event": ingested.get("siem_event", {}),
                "code": analyzed.get("code", ""),
                "tokens_in": analyzed.get("tokens_in", 0),
                "tokens_out": analyzed.get("tokens_out", 0),
                "path_taken": path_taken,
                "generated_code": analyzed.get("code", ""),
                "trace_id": trace_id,
            },
            start_to_close_timeout=timedelta(seconds=30),
        )

        return stored
