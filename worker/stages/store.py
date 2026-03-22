"""
Stage 5: STORE — Persist all investigation artifacts.
NO LLM calls. DB writes only.

Self-contained: imports psycopg2 directly.
Does NOT import from _legacy_activities.py or entity_graph.py.
"""
import os
import json
import time
from dataclasses import asdict

import psycopg2

from temporalio import activity
from stages import StoreOutput

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
FAST_FILL = os.environ.get("HYDRA_FAST_FILL", "false").lower() == "true"


def _get_db():
    return psycopg2.connect(DATABASE_URL)


def _get_worker_id():
    import socket, random, string
    host = socket.gethostname()
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{host}-{suffix}"


# --- Task status update ---
def _update_task_status(conn, task_id: str, status: str, output: dict,
                        tokens_in: int = 0, tokens_out: int = 0,
                        execution_ms: int = 0, severity: str = None,
                        error_message: str = None, model_name: str = "unknown"):
    """Update agent_tasks with final status."""
    worker_id = _get_worker_id()
    human_review_threshold = int(os.environ.get("HYDRA_HUMAN_REVIEW_THRESHOLD", "60"))

    risk_score = 0
    if isinstance(output, dict):
        risk_score = output.get("risk_score", 0) or 0

    needs_review = False
    review_reason = None
    if status != "completed":
        needs_review = True
        review_reason = error_message or "Investigation failed"
    elif risk_score < human_review_threshold:
        needs_review = True
        review_reason = f"Risk score {risk_score} below threshold {human_review_threshold}"

    with conn.cursor() as cur:
        cur.execute("""
            UPDATE agent_tasks
            SET status = %s, output = %s, error_message = %s,
                tokens_used_input = %s, tokens_used_output = %s, execution_ms = %s,
                severity = %s, worker_id = COALESCE(%s, worker_id),
                needs_human_review = %s, review_reason = %s,
                model_name = %s,
                completed_at = NOW()
            WHERE id = %s
        """, (
            status, json.dumps(output), error_message,
            tokens_in, tokens_out, execution_ms,
            severity, worker_id,
            needs_review, review_reason,
            model_name,
            task_id,
        ))


# --- Investigation memory ---
def _save_pattern(conn, task_type: str, alert_sig: str, code: str,
                  iocs: list, findings: list, risk_score: int, success: bool):
    """Save investigation pattern to memory table. No LLM."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO investigation_memory
                (task_type, alert_signature, code_template, iocs_found,
                 findings_found, risk_score, success)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                task_type, alert_sig, (code or "")[:10000],
                json.dumps(iocs), json.dumps(findings),
                risk_score, success,
            ))
    except Exception as e:
        print(f"Pattern save failed (non-fatal): {e}")


# --- Investigation row (no embedding) ---
def _create_investigation(conn, tenant_id: str, task_id: str, verdict: str,
                          risk_score: int, confidence: float, summary: str,
                          model_name: str = "unknown"):
    """Insert investigations row without embedding. Returns investigation_id."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO investigations
                (tenant_id, task_id, verdict, risk_score, confidence,
                 summary, source, model_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (tenant_id, task_id, verdict, risk_score, confidence,
                  (summary or "")[:2000], "production", model_name))
            row = cur.fetchone()
            return str(row[0]) if row else None
    except Exception as e:
        print(f"Investigation insert failed (non-fatal): {e}")
        return None


# --- Severity from risk score ---
def _severity_from_risk(risk_score: int) -> str:
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    return "informational"


# --- Main entry point ---
@activity.defn
async def store_investigation(data: dict) -> dict:
    """
    Stage 5: Persist all investigation artifacts.
    NO LLM calls. DB writes only.

    Input: merged dict from AssessOutput + ExecuteOutput + task metadata
    Returns: dict (serializable StoreOutput fields)
    """
    task_id = data.get("task_id", "")
    tenant_id = data.get("tenant_id", "")
    status = data.get("status", "completed")
    verdict = data.get("verdict", "inconclusive")
    risk_score = data.get("risk_score", 0)
    confidence = data.get("confidence", 0.5)
    memory_summary = data.get("memory_summary", "")
    stdout = data.get("stdout", "")
    iocs = data.get("iocs", [])
    findings = data.get("findings", [])
    recommendations = data.get("recommendations", [])
    code = data.get("code", "")
    tokens_in = data.get("tokens_in", 0)
    tokens_out = data.get("tokens_out", 0)
    execution_ms = data.get("execution_ms", 0)
    task_type = data.get("task_type", "")
    model_name = data.get("model_name", "unknown")
    siem_event = data.get("siem_event", {})

    severity = _severity_from_risk(risk_score)
    investigation_id = None

    conn = _get_db()
    try:
        # 1. Update task status
        output = {
            "stdout": stdout,
            "iocs": iocs,
            "findings": findings,
            "risk_score": risk_score,
            "verdict": verdict,
            "recommendations": recommendations,
            "model_used": model_name,
        }
        _update_task_status(
            conn, task_id, status, output,
            tokens_in=tokens_in, tokens_out=tokens_out,
            execution_ms=execution_ms, severity=severity,
            model_name=model_name,
        )

        # 2. Save investigation pattern (no LLM)
        if status == "completed":
            _save_pattern(
                conn, task_type, siem_event.get("rule_name", ""),
                code, iocs, findings, risk_score, True,
            )

        # 3. Create investigation row (skip embedding in FAST_FILL)
        if status == "completed" and not FAST_FILL:
            investigation_id = _create_investigation(
                conn, tenant_id, task_id, verdict,
                risk_score, confidence, memory_summary or stdout[:2000],
                model_name=model_name,
            )

        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Store failed: {e}")
        status = "failed"
    finally:
        conn.close()

    result = StoreOutput(
        task_id=task_id,
        status=status,
        investigation_id=investigation_id,
        memory_saved=status == "completed",
        pattern_saved=status == "completed",
    )

    return asdict(result)
