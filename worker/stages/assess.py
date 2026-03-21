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
async def _llm_summary(stdout: str, task_type: str) -> str:
    """Call LLM to generate a 2-3 sentence investigation summary."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                LITELLM_URL,
                headers={"Authorization": f"Bearer {LITELLM_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "hydra-fast",
                    "messages": [
                        {"role": "system", "content": "Summarize this investigation in 2-3 sentences."},
                        {"role": "user", "content": stdout[:2000]},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 200,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"LLM summary failed (non-fatal): {e}")
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

    verdict = _derive_verdict(risk_score, len(iocs), len(findings))
    severity = _severity_from_risk(risk_score)
    fp_conf = _fp_confidence(risk_score, len(iocs))

    # Summary
    if FAST_FILL:
        summary = _template_summary(task_type, findings, iocs, risk_score)
    else:
        summary = await _llm_summary(stdout, task_type)
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

    return asdict(result)
