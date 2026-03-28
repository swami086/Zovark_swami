"""Fine-tuning pipeline Temporal workflow + activities."""

import json
import os
import time
from datetime import timedelta
from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    from finetuning.data_export import export_training_data, write_jsonl
    from finetuning.evaluator import evaluate_model
    import psycopg2


DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")


def _get_db():
    return psycopg2.connect(DATABASE_URL)


# ============================================================
# ACTIVITIES
# ============================================================

@activity.defn
async def export_finetuning_data(data: dict) -> dict:
    """Export training data from investigations."""
    min_quality = data.get("min_quality_score", 0.7)
    limit = data.get("limit", 1000)
    output_dir = data.get("output_dir", "/tmp/zovark-finetuning")

    os.makedirs(output_dir, exist_ok=True)

    examples = export_training_data(min_quality_score=min_quality, limit=limit)

    output_path = os.path.join(output_dir, f"training_data_{int(time.time())}.jsonl")
    write_jsonl(examples, output_path)

    return {
        "examples_count": len(examples),
        "output_path": output_path,
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

    with open(output_path) as f:
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
    """Run benchmark evaluation on a model."""
    model_name = data.get("model", "fast")
    return evaluate_model(model_name=model_name)


@activity.defn
async def create_finetuning_job(data: dict) -> dict:
    """Create a fine-tuning job record in the database."""
    conn = _get_db()
    cur = conn.cursor()

    job_id = data.get("job_id")
    cur.execute("""
        INSERT INTO finetuning_jobs (id, status, config, training_examples, quality_stats, created_at)
        VALUES (%s, 'pending', %s, %s, %s, NOW())
        ON CONFLICT (id) DO UPDATE SET
            status = EXCLUDED.status,
            config = EXCLUDED.config,
            training_examples = EXCLUDED.training_examples,
            quality_stats = EXCLUDED.quality_stats
        RETURNING id
    """, (
        job_id,
        json.dumps(data.get("config", {})),
        data.get("examples_count", 0),
        json.dumps(data.get("quality_stats", {})),
    ))

    conn.commit()
    cur.close()
    conn.close()

    return {"job_id": job_id, "status": "created"}


@activity.defn
async def update_finetuning_job(data: dict) -> dict:
    """Update fine-tuning job status and results."""
    conn = _get_db()
    cur = conn.cursor()

    job_id = data["job_id"]
    status = data.get("status", "completed")
    eval_results = data.get("evaluation_results")

    if eval_results:
        cur.execute("""
            UPDATE finetuning_jobs
            SET status = %s, evaluation_results = %s, completed_at = NOW()
            WHERE id = %s
        """, (status, json.dumps(eval_results), job_id))
    else:
        cur.execute("""
            UPDATE finetuning_jobs SET status = %s WHERE id = %s
        """, (status, job_id))

    conn.commit()
    cur.close()
    conn.close()

    return {"job_id": job_id, "status": status}


# ============================================================
# WORKFLOW
# ============================================================

@workflow.defn
class FineTuningPipelineWorkflow:
    """Orchestrates the fine-tuning data pipeline:
    1. Export training data from investigations
    2. Score quality
    3. Run baseline evaluation
    4. Record results
    """

    @workflow.run
    async def run(self, params: dict) -> dict:
        job_id = params.get("job_id", f"ft-{int(time.time())}")
        min_quality = params.get("min_quality_score", 0.7)
        limit = params.get("limit", 1000)
        model = params.get("model", "fast")

        workflow.logger.info(f"Fine-tuning pipeline started: {job_id}")

        # 1. Export training data
        export_result = await workflow.execute_activity(
            export_finetuning_data,
            {"min_quality_score": min_quality, "limit": limit},
            schedule_to_close_timeout=timedelta(minutes=5),
        )

        if export_result.get("examples_count", 0) == 0:
            return {"job_id": job_id, "status": "skipped", "reason": "no qualifying training examples"}

        # 2. Score quality
        quality_stats = await workflow.execute_activity(
            score_training_quality,
            {"output_path": export_result["output_path"]},
            schedule_to_close_timeout=timedelta(minutes=2),
        )

        # 3. Create job record
        await workflow.execute_activity(
            create_finetuning_job,
            {
                "job_id": job_id,
                "config": {"min_quality_score": min_quality, "limit": limit, "model": model},
                "examples_count": export_result["examples_count"],
                "quality_stats": quality_stats,
            },
            schedule_to_close_timeout=timedelta(seconds=30),
        )

        # 4. Run model evaluation
        eval_results = await workflow.execute_activity(
            run_model_evaluation,
            {"model": model},
            schedule_to_close_timeout=timedelta(minutes=10),
        )

        # 5. Update job with results
        await workflow.execute_activity(
            update_finetuning_job,
            {
                "job_id": job_id,
                "status": "completed",
                "evaluation_results": eval_results,
            },
            schedule_to_close_timeout=timedelta(seconds=30),
        )

        workflow.logger.info(f"Fine-tuning pipeline completed: {job_id}")

        return {
            "job_id": job_id,
            "status": "completed",
            "training_examples": export_result["examples_count"],
            "quality_stats": quality_stats,
            "evaluation": {
                "model": model,
                "average_score": eval_results.get("average_score", 0),
                "benchmark_count": eval_results.get("benchmark_count", 0),
            },
        }
