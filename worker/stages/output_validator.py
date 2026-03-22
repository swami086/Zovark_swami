"""
Output schema validation for investigation results.

Validates that sandbox output and assess stage output conform to the
required schema before reaching the dashboard or being stored.

Used by: stages/assess.py (post-LLM validation)
"""
from typing import Tuple


# Valid verdicts that the pipeline can produce
VALID_VERDICTS = {
    "true_positive", "false_positive", "suspicious",
    "benign", "needs_manual_review", "inconclusive",
}


def validate_investigation_output(output: dict) -> Tuple[bool, str]:
    """Validate investigation output matches required schema.

    Returns:
        (is_valid, error_message) — error_message is "valid" when is_valid is True.
    """
    if not isinstance(output, dict):
        return False, f"Output is {type(output).__name__}, expected dict"

    # --- Required keys and types ---
    required = {
        "findings": list,
        "iocs": list,
        "risk_score": (int, float),
        "recommendations": list,
    }
    for key, expected_type in required.items():
        if key not in output:
            return False, f"Missing required key: {key}"
        if not isinstance(output[key], expected_type):
            return False, f"{key}: expected {expected_type}, got {type(output[key]).__name__}"

    # --- Findings must be non-empty ---
    if len(output.get("findings", [])) == 0:
        return False, "findings must be non-empty"

    # --- risk_score must be 0-100 ---
    risk = output.get("risk_score", -1)
    if not (0 <= risk <= 100):
        return False, f"risk_score must be 0-100, got {risk}"

    # --- IOCs must have type and value ---
    for i, ioc in enumerate(output.get("iocs", [])):
        if not isinstance(ioc, dict) or "type" not in ioc or "value" not in ioc:
            return False, f"IOC[{i}] missing type or value: {ioc}"

    # --- Verdict validation (optional field) ---
    verdict = output.get("verdict")
    if verdict and verdict not in VALID_VERDICTS:
        return False, f"Invalid verdict: {verdict}. Must be one of: {VALID_VERDICTS}"

    return True, "valid"


def safe_default_output() -> dict:
    """Return a safe default output when validation fails after retries."""
    return {
        "findings": [
            "Investigation output failed validation -- manual review required"
        ],
        "iocs": [],
        "risk_score": 50,
        "verdict": "needs_manual_review",
        "recommendations": [
            "Manually review the original alert"
        ],
    }
