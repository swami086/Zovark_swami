"""
Stage 4: ASSESS — Generate verdict and investigation summary.
LLM calls: entity extraction (optional), FP analysis (optional).

This is one of TWO files that call the LLM (the other is Stage 2 ANALYZE).
All LLM verdict/summary calls are contained HERE.

Self-contained: imports httpx, psycopg2 directly.
Does NOT import from _legacy_activities.py or intelligence/fp_analyzer.py.
"""
import os
import re
import json
import time
from typing import List, Dict
from dataclasses import asdict

import httpx

from temporalio import activity
from stages import AssessOutput
from stages.llm_gateway import llm_call
from stages.model_router import get_model_config
from stages.output_validator import validate_investigation_output, safe_default_output
from stages.mitre_mapping import get_mitre_techniques

FAST_FILL = os.environ.get("HYDRA_FAST_FILL", "false").lower() == "true"
LITELLM_URL = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")


# --- Verdict derivation ---
def _derive_verdict(risk_score: int, ioc_count: int, finding_count: int) -> str:
    if risk_score >= 80 and ioc_count >= 3:
        return "true_positive"
    elif risk_score >= 60 or ioc_count >= 2:
        return "suspicious"
    elif finding_count == 0 and ioc_count == 0:
        return "benign"
    return "inconclusive"


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


# --- Template summary (no LLM) ---
def _template_summary(task_type: str, findings: list, iocs: list, risk_score: int) -> str:
    """Generate a memory summary without LLM."""
    ioc_types = set()
    for ioc in iocs:
        if isinstance(ioc, dict):
            ioc_types.add(ioc.get("type", "unknown"))
    return (
        f"Investigated {task_type} alert. "
        f"Found {len(findings)} findings and {len(iocs)} IOCs ({', '.join(ioc_types) or 'none'}). "
        f"Risk score: {risk_score}."
    )


# --- LLM summary (optional) ---
async def _llm_summary(stdout: str, task_type: str, task_id: str = "", tenant_id: str = "") -> str:
    """Call LLM to generate a 2-3 sentence investigation summary."""
    try:
        summary_config = get_model_config(severity="low", task_type=task_type)
        summary_config.update({"temperature": 0.1, "max_tokens": 200})
        result = await llm_call(
            prompt=stdout[:2000],
            system_prompt="Summarize this investigation in 2-3 sentences.",
            model_config=summary_config,
            task_id=task_id,
            stage="assess",
            task_type=task_type,
            tenant_id=tenant_id,
            timeout=120.0,
        )
        return result["content"]
    except Exception as e:
        print(f"LLM summary failed (non-fatal): {type(e).__name__}: {e}")
        return ""


# --- FP confidence (simple rules, no LLM) ---
def _fp_confidence(risk_score: int, ioc_count: int) -> float:
    """Rule-based FP confidence. Higher = more likely false positive."""
    if risk_score >= 80 and ioc_count >= 3:
        return 0.1  # Very likely real
    elif risk_score >= 60:
        return 0.3
    elif risk_score >= 40:
        return 0.5
    elif ioc_count == 0:
        return 0.8  # Likely FP
    return 0.6


# --- Validation failure logging ---
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")


def _log_validation_failure(task_id: str, tenant_id: str, task_type: str, error_msg: str):
    """Log validation failure to llm_audit_log (best-effort, never raises)."""
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO llm_audit_log
                       (tenant_id, task_id, stage, task_type, model_name, status, error_message, created_at)
                       VALUES (%s, %s, 'assess', %s, 'output_validator', 'validation_failed', %s, NOW())""",
                    (tenant_id, task_id, task_type, error_msg),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        # Never let audit logging break the pipeline
        print(f"Validation failure logging failed (non-fatal): {e}")


# --- Main entry point ---
@activity.defn
async def assess_results(data: dict) -> dict:
    """
    Stage 4: Generate verdict and investigation summary.

    FAST_FILL: template verdict based on IOC count (no LLM).
    Normal: optional LLM summary + rules-based FP analysis.

    Input: ExecuteOutput fields + task metadata
    Returns: dict (serializable AssessOutput fields)
    """
    task_id = data.get("task_id", "")
    tenant_id = data.get("tenant_id", "")
    stdout = data.get("stdout", "")
    iocs = data.get("iocs", [])
    findings = data.get("findings", [])
    risk_score = data.get("risk_score", 0)
    recommendations = data.get("recommendations", [])
    task_type = data.get("task_type", "")

    # --- Schema validation of sandbox output ---
    # Validate the data coming from execute stage (findings, iocs, risk_score, recommendations)
    sandbox_output = {
        "findings": findings,
        "iocs": iocs,
        "risk_score": risk_score,
        "recommendations": recommendations,
    }
    is_valid, validation_error = validate_investigation_output(sandbox_output)
    if not is_valid:
        activity.logger.warning(
            f"Sandbox output validation failed for task {task_id}: {validation_error}"
        )
        # Log validation failure to llm_audit_log (best-effort)
        _log_validation_failure(task_id, tenant_id, task_type, validation_error)
        # Use safe defaults — NEVER let invalid output reach the dashboard
        defaults = safe_default_output()
        findings = defaults["findings"]
        iocs = defaults["iocs"]
        risk_score = defaults["risk_score"]
        recommendations = defaults["recommendations"]

    verdict = _derive_verdict(risk_score, len(iocs), len(findings))
    severity = _severity_from_risk(risk_score)
    fp_conf = _fp_confidence(risk_score, len(iocs))

    # If validation failed, override verdict
    if not is_valid:
        verdict = "needs_manual_review"

    # Summary
    if FAST_FILL:
        summary = _template_summary(task_type, findings, iocs, risk_score)
    else:
        summary = await _llm_summary(stdout, task_type, task_id=task_id, tenant_id=tenant_id)
        if not summary:
            summary = _template_summary(task_type, findings, iocs, risk_score)

    result = AssessOutput(
        verdict=verdict,
        risk_score=risk_score,
        severity=severity,
        confidence=1.0 - fp_conf,
        false_positive_confidence=fp_conf,
        recommendations=recommendations,
        memory_summary=summary,
    )

    out = asdict(result)
    out["mitre_attack"] = get_mitre_techniques(task_type)
    out["investigation_metadata"] = {
        "pipeline_version": "v2",
        "schema_validated": is_valid,
    }
    return out
