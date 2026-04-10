"""Fine-tuning pipeline Temporal workflow + activities.

Exports SFT + DPO JSONL artifacts and notifies the platform (audit_events) when data
is ready. When ``ZOVARK_REDPANDA_BROKERS`` is set, also publishes
``platform.finetuning.data_ready.{tenant_id}`` for downstream MLOps (Ticket 5).
Actual GPU training is triggered outside the worker — see governance_config /
enterprise CI. No in-cluster ``trigger_training`` activity.
"""

import asyncio
import json
import os
import time
from datetime import timedelta
from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    from database.pool_manager import pooled_connection
    from finetuning.data_export import (
        export_training_data,
        write_jsonl,
        export_dpo_preference_rows,
        write_dpo_jsonl,
    )
    from finetuning.evaluator import evaluate_model, evaluate_model_pair
    from finetuning.platform_bus import (
        build_finetuning_data_ready_envelope,
        emit_finetuning_data_ready_sync,
    )

SYSTEM_TENANT_ID = "00000000-0000-0000-0000-000000000001"


@activity.defn
async def export_finetuning_data(data: dict) -> dict:
    """Export training data from investigations (+ DPO preferences when analyst_feedback exists)."""
    min_quality = data.get("min_quality_score", 0.7)
    limit = data.get("limit", 1000)
    dpo_limit = data.get("dpo_limit", 5000)
    output_dir = data.get("output_dir", "/tmp/zovark-finetuning")

    os.makedirs(output_dir, exist_ok=True)

    examples = export_training_data(min_quality_score=min_quality, limit=limit)

    output_path = os.path.join(output_dir, f"training_data_{int(time.time())}.jsonl")
    write_jsonl(examples, output_path)

    dpo_rows = export_dpo_preference_rows(limit=dpo_limit)
    dpo_path = ""
    if dpo_rows:
        dpo_path = os.path.join(output_dir, f"dpo_preferences_{int(time.time())}.jsonl")
        write_dpo_jsonl(dpo_rows, dpo_path)

    return {
        "examples_count": len(examples),
        "output_path": output_path,
        "dpo_output_path": dpo_path,
        "dpo_rows": len(dpo_rows),
        "min_quality_score": min_quality,
    }


@activity.defn
async def score_training_quality(data: dict) -> dict:
    """Compute aggregate quality statistics for training data."""
    output_path = data.get("output_path", "")
    if not os.path.exists(output_path):
        return {"error": "output file not found"}

    scores = []
    task_types = {}
    verdicts = {}

    with open(output_path, encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            meta = record.get("metadata", {})
            qs = meta.get("quality_score", 0)
            scores.append(qs)

            tt = meta.get("task_type", "unknown")
            task_types[tt] = task_types.get(tt, 0) + 1

            v = meta.get("verdict", "unknown")
            verdicts[v] = verdicts.get(v, 0) + 1

    if not scores:
        return {"error": "no training examples found", "count": 0}

    return {
        "count": len(scores),
        "avg_quality": round(sum(scores) / len(scores), 3),
        "min_quality": round(min(scores), 3),
        "max_quality": round(max(scores), 3),
        "task_type_distribution": task_types,
        "verdict_distribution": verdicts,
    }


@activity.defn
async def run_model_evaluation(data: dict) -> dict:
    """Run 50-case baseline vs candidate verdict comparison (zero-flip gate) + single-model scores."""
    import os as _os

    fallback = (data.get("model") or "fast").strip()
    baseline = (
        (data.get("baseline_model") or _os.environ.get("ZOVARK_FINETUNE_EVAL_BASELINE_MODEL") or fallback)
        .strip()
    )
    candidate = (data.get("candidate_model") or fallback).strip()

    pair = evaluate_model_pair(baseline, candidate, limit=50)
    single = evaluate_model(model_name=candidate)

    return {
        "passed": bool(pair.get("passed")),
        "baseline_model": baseline,
        "candidate_model": candidate,
        "pair_evaluation": pair,
        "single_model_benchmark": single,
    }


@activity.defn
async def notify_platform_data_ready(data: dict) -> dict:
    """Record that export artifacts are ready; platform-side pipeline runs training."""
    tenant_id = data.get("tenant_id") or SYSTEM_TENANT_ID
    job_id = data.get("job_id") or ""
    meta = {
        "job_id": job_id,
        "training_path": data.get("output_path"),
        "dpo_path": data.get("dpo_output_path") or "",
        "examples_count": data.get("examples_count", 0),
        "dpo_rows": data.get("dpo_rows", 0),
        "governance_hint": (
            "Trigger model training from your platform (CI / MLOps). "
            "Set autonomy and training hooks in governance_config; worker does not enqueue GPU jobs."
        ),
    }
    try:
        with pooled_connection("background") as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_events
                    (tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
                    VALUES (%s::uuid, %s, %s, %s, %s, %s)
                    """,
                    (
                        tenant_id,
                        "platform_data_ready",
                        "system",
                        "finetuning_job",
                        None,
                        json.dumps(meta),
                    ),
                )
        envelope = build_finetuning_data_ready_envelope(
            tenant_id,
            job_id=job_id,
            training_path=data.get("output_path") or "",
            dpo_path=data.get("dpo_output_path") or "",
            examples_count=data.get("examples_count", 0),
            dpo_rows=data.get("dpo_rows", 0),
        )
        bus_result = await asyncio.to_thread(emit_finetuning_data_ready_sync, tenant_id, envelope)
        return {
            "notified": True,
            "event_type": "platform_data_ready",
            "redpanda": bus_result,
        }
    except Exception as e:
        return {"notified": False, "error": str(e)[:500]}


@activity.defn
async def create_finetuning_job(data: dict) -> dict:
    """Create a fine-tuning job record in the database."""
    job_id = data.get("job_id")
    with pooled_connection("background") as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO finetuning_jobs (id, status, config, training_examples, quality_stats, created_at)
            VALUES (%s, 'pending', %s, %s, %s, NOW())
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                config = EXCLUDED.config,
                training_examples = EXCLUDED.training_examples,
                quality_stats = EXCLUDED.quality_stats
            RETURNING id
            """,
            (
                job_id,
                json.dumps(data.get("config", {})),
                data.get("examples_count", 0),
                json.dumps(data.get("quality_stats", {})),
            ),
        )
        cur.close()

    return {"job_id": job_id, "status": "created"}


@activity.defn
async def update_finetuning_job(data: dict) -> dict:
    """Update fine-tuning job status and results."""
    job_id = data["job_id"]
    status = data.get("status", "completed")
    eval_results = data.get("evaluation_results")

    with pooled_connection("background") as conn:
        cur = conn.cursor()

        if eval_results:
            cur.execute(
                """
                UPDATE finetuning_jobs
                SET status = %s, evaluation_results = %s, completed_at = NOW()
                WHERE id = %s
                """,
                (status, json.dumps(eval_results), job_id),
            )
        else:
            cur.execute(
                """
                UPDATE finetuning_jobs SET status = %s WHERE id = %s
                """,
                (status, job_id),
            )

        cur.close()

    return {"job_id": job_id, "status": status}


@workflow.defn
class FineTuningPipelineWorkflow:
    """Export training artifacts, evaluate, audit-notify platform (no GPU training here)."""

    @workflow.run
    async def run(self, params: dict) -> dict:
        job_id = params.get("job_id", f"ft-{int(time.time())}")
        min_quality = params.get("min_quality_score", 0.7)
        limit = params.get("limit", 1000)
        model = params.get("model", "fast")
        baseline_model = params.get("baseline_model")
        candidate_model = params.get("candidate_model")

        workflow.logger.info(f"Fine-tuning pipeline started: {job_id}")

        tenant_id = params.get("tenant_id") or SYSTEM_TENANT_ID

        export_result = await workflow.execute_activity(
            export_finetuning_data,
            {"min_quality_score": min_quality, "limit": limit},
            schedule_to_close_timeout=timedelta(minutes=5),
        )

        if export_result.get("examples_count", 0) == 0:
            return {"job_id": job_id, "status": "skipped", "reason": "no qualifying training examples"}

        quality_stats = await workflow.execute_activity(
            score_training_quality,
            {"output_path": export_result["output_path"]},
            schedule_to_close_timeout=timedelta(minutes=2),
        )

        await workflow.execute_activity(
            create_finetuning_job,
            {
                "job_id": job_id,
                "config": {
                    "min_quality_score": min_quality,
                    "limit": limit,
                    "model": model,
                    "baseline_model": baseline_model,
                    "candidate_model": candidate_model,
                },
                "examples_count": export_result["examples_count"],
                "quality_stats": quality_stats,
            },
            schedule_to_close_timeout=timedelta(seconds=30),
        )

        eval_results = await workflow.execute_activity(
            run_model_evaluation,
            {
                "model": model,
                "baseline_model": baseline_model,
                "candidate_model": candidate_model,
            },
            schedule_to_close_timeout=timedelta(minutes=90),
        )

        if not eval_results.get("passed", False):
            await workflow.execute_activity(
                update_finetuning_job,
                {
                    "job_id": job_id,
                    "status": "failed",
                    "evaluation_results": eval_results,
                },
                schedule_to_close_timeout=timedelta(seconds=30),
            )
            workflow.logger.warning(
                f"Fine-tuning pipeline failed verdict gate: {job_id} "
                f"flips={len(eval_results.get('pair_evaluation', {}).get('verdict_flips', []))} "
                f"errors={len(eval_results.get('pair_evaluation', {}).get('errors', []))}"
            )
            return {
                "job_id": job_id,
                "status": "failed",
                "reason": "verdict_flip_or_eval_error",
                "training_examples": export_result["examples_count"],
                "quality_stats": quality_stats,
                "evaluation_results": eval_results,
            }

        await workflow.execute_activity(
            update_finetuning_job,
            {
                "job_id": job_id,
                "status": "completed",
                "evaluation_results": eval_results,
            },
            schedule_to_close_timeout=timedelta(seconds=30),
        )

        notify_result = await workflow.execute_activity(
            notify_platform_data_ready,
            {
                "tenant_id": tenant_id,
                "job_id": job_id,
                "output_path": export_result["output_path"],
                "dpo_output_path": export_result.get("dpo_output_path", ""),
                "examples_count": export_result["examples_count"],
                "dpo_rows": export_result.get("dpo_rows", 0),
            },
            schedule_to_close_timeout=timedelta(seconds=30),
        )

        workflow.logger.info(f"Fine-tuning pipeline completed: {job_id}")

        bench = eval_results.get("single_model_benchmark") or {}
        return {
            "job_id": job_id,
            "status": "completed",
            "training_examples": export_result["examples_count"],
            "dpo_rows": export_result.get("dpo_rows", 0),
            "quality_stats": quality_stats,
            "platform_notify": notify_result,
            "evaluation": {
                "baseline_model": eval_results.get("baseline_model"),
                "candidate_model": eval_results.get("candidate_model"),
                "pair_passed": True,
                "average_score": bench.get("average_score", 0),
                "benchmark_count": bench.get("benchmark_count", 0),
            },
        }
