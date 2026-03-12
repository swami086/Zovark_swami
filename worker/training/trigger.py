"""Auto-retrain trigger activity (Issue #55).

Monitors investigation_feedback for accuracy drops.
If accuracy < 80% over last 100 investigations, triggers FineTuningPipelineWorkflow.
"""

import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


# Accuracy threshold below which retraining is triggered
ACCURACY_THRESHOLD = 0.80
# Number of recent investigations to evaluate
EVALUATION_WINDOW = 100


@activity.defn
async def check_retrain_needed(data: dict) -> dict:
    """Check if model retraining is needed based on investigation feedback accuracy.

    Input: {threshold: 0.80, window: 100, tenant_id: optional}
    Returns: {
        retrain_needed: bool, accuracy: float,
        total_feedback: int, correct_count: int,
        threshold: float, window: int,
        decision_reason: str
    }
    """
    threshold = data.get("threshold", ACCURACY_THRESHOLD)
    window = data.get("window", EVALUATION_WINDOW)
    tenant_id = data.get("tenant_id")

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get recent feedback with verdict correctness
            query = """
                SELECT verdict_correct, false_positive, missed_threat,
                       analyst_confidence, created_at
                FROM investigation_feedback
            """
            params = []
            if tenant_id:
                query += " WHERE tenant_id = %s"
                params.append(tenant_id)

            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(window)

            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]

        if not rows:
            return {
                "retrain_needed": False,
                "accuracy": 1.0,
                "total_feedback": 0,
                "correct_count": 0,
                "threshold": threshold,
                "window": window,
                "decision_reason": "No feedback data available",
            }

        total = len(rows)
        correct = sum(1 for r in rows if r.get("verdict_correct") is True)
        fp_count = sum(1 for r in rows if r.get("false_positive") is True)
        missed_count = sum(1 for r in rows if r.get("missed_threat") is True)

        accuracy = correct / total if total > 0 else 1.0
        retrain_needed = accuracy < threshold and total >= 10  # Need at least 10 samples

        decision_reason = ""
        if retrain_needed:
            decision_reason = (
                f"Accuracy {accuracy:.1%} below threshold {threshold:.0%} "
                f"({correct}/{total} correct, {fp_count} FP, {missed_count} missed)"
            )
        elif total < 10:
            decision_reason = f"Insufficient feedback data ({total} samples, need >= 10)"
        else:
            decision_reason = f"Accuracy {accuracy:.1%} meets threshold {threshold:.0%}"

        # Log decision to audit_events
        _log_retrain_decision(tenant_id, retrain_needed, accuracy, total, decision_reason)

        return {
            "retrain_needed": retrain_needed,
            "accuracy": round(accuracy, 3),
            "total_feedback": total,
            "correct_count": correct,
            "false_positives": fp_count,
            "missed_threats": missed_count,
            "threshold": threshold,
            "window": window,
            "decision_reason": decision_reason,
        }

    finally:
        conn.close()


def _log_retrain_decision(tenant_id, retrain_needed, accuracy, total, reason):
    """Log retrain decision to audit_events. Fire-and-forget."""
    try:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO audit_events
                    (tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    tenant_id,
                    "retrain_check",
                    "system",
                    "model",
                    "hydra-standard",
                    json.dumps({
                        "retrain_needed": retrain_needed,
                        "accuracy": accuracy,
                        "total_feedback": total,
                        "reason": reason,
                    }),
                ))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"training_trigger: audit log failed (non-fatal): {e}")
