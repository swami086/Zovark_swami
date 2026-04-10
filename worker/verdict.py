"""Shared verdict derivation and severity mapping.

Single source of truth — imported by runner.py, assess.py, and store.py.

Four-band verdict policy:
    risk >= 75  → true_positive
    50 ≤ risk < 75 → suspicious
    25 ≤ risk < 50 → needs_review
    risk < 25   → benign
"""


def derive_verdict(risk_score: int, ioc_count: int, finding_count: int, execution_mode: str = "sandbox") -> str:
    """Derive investigation verdict from risk score and evidence counts."""
    if execution_mode == "sandbox" and risk_score == 0 and finding_count <= 1:
        return "error"
    if risk_score >= 75:
        return "true_positive"
    if risk_score >= 50:
        return "suspicious"
    if risk_score >= 25:
        return "needs_review"
    return "benign"


def severity_from_risk(risk_score: int) -> str:
    """Map numeric risk score to severity label."""
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    return "informational"
