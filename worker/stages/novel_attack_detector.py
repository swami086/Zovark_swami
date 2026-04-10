"""
Detect novel / high-risk investigations suitable for privacy-preserving platform export.

Path D: investigations that used dynamic LLM tool selection (path_taken ``C`` or ``D``)
with elevated risk and actionable verdicts. Emits **behavioral abstractions only**
(no raw IOCs or host identities).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Path D in the ticket: treat explicit D and high-risk C (novel tool-selection path)
_NOVEL_PATHS = frozenset({"C", "D"})
_HIGH_VERDICTS = frozenset({"true_positive", "suspicious"})
_DEFAULT_RISK_FLOOR = 60


def _risk_score(output: Dict[str, Any]) -> int:
    raw = output.get("risk_score")
    if raw is None and isinstance(output.get("output"), dict):
        raw = output["output"].get("risk_score")
    try:
        return max(0, min(100, int(raw)))
    except (TypeError, ValueError):
        return 0


def _verdict(output: Dict[str, Any]) -> str:
    v = output.get("verdict")
    if v is None and isinstance(output.get("output"), dict):
        v = output["output"].get("verdict")
    return str(v or "").lower().strip()


def _path_taken(output: Dict[str, Any]) -> str:
    p = output.get("path_taken")
    if p is None and isinstance(output.get("output"), dict):
        p = output["output"].get("path_taken")
    return str(p or "").strip().upper()


def _task_type(output: Dict[str, Any]) -> str:
    t = output.get("task_type")
    if t is None and isinstance(output.get("input"), dict):
        t = output["input"].get("task_type")
    return str(t or "unknown")


def is_novel_attack_candidate(
    investigation_record: Dict[str, Any],
    *,
    risk_floor: int = _DEFAULT_RISK_FLOOR,
) -> bool:
    """
    True when investigation matches Path-D-style novelty + high-risk signal.
    """
    path = _path_taken(investigation_record)
    if path not in _NOVEL_PATHS:
        return False
    if _verdict(investigation_record) not in _HIGH_VERDICTS:
        return False
    if _risk_score(investigation_record) < risk_floor:
        return False
    return True


def behavioral_abstraction(investigation_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strip to non-identifying behavioral features for platform / DPO flywheel.
    """
    out = investigation_record.get("output") if isinstance(investigation_record.get("output"), dict) else {}
    mitre = out.get("mitre_techniques") or out.get("mitre") or []
    if isinstance(mitre, dict):
        mitre = [mitre]
    findings = out.get("findings")
    if isinstance(findings, list):
        findings_summary = [str(f)[:200] for f in findings[:5]]
    else:
        findings_summary = []

    return {
        "schema": "zovark.novel_attack.abstraction.v1",
        "task_type": _task_type(investigation_record),
        "path_taken": _path_taken(investigation_record),
        "verdict": _verdict(investigation_record),
        "risk_band": _risk_band(_risk_score(investigation_record)),
        "mitre_techniques": mitre if isinstance(mitre, list) else [],
        "finding_classes": findings_summary,
        "plan_executed": bool(out.get("plan_executed") or out.get("tools_executed")),
    }


def _risk_band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def filter_novel_attacks(
    investigations: List[Dict[str, Any]],
    *,
    risk_floor: int = _DEFAULT_RISK_FLOOR,
) -> List[Dict[str, Any]]:
    return [behavioral_abstraction(rec) for rec in investigations if is_novel_attack_candidate(rec, risk_floor=risk_floor)]
