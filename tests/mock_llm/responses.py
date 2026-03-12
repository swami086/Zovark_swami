"""Canned LLM responses for different alert types.

Used by the mock LLM server to return realistic investigation responses
without requiring a real LLM inference engine.
"""

import json

# Standard investigation response template
INVESTIGATION_RESPONSE = json.dumps({
    "verdict": "suspicious",
    "confidence": 0.82,
    "risk_score": 65,
    "summary": "Analysis indicates potential brute force activity. Multiple failed login attempts "
               "detected from a single source IP targeting the root account. The pattern shows "
               "rapid successive attempts consistent with automated credential stuffing.",
    "findings": [
        {
            "type": "brute_force",
            "severity": "high",
            "description": "47 failed login attempts from 192.168.1.100 in 3 minutes",
            "indicators": ["192.168.1.100", "root", "ssh"],
            "mitre_technique": "T1110.001",
        }
    ],
    "entities": [
        {"type": "ip", "value": "192.168.1.100", "role": "attacker"},
        {"type": "user", "value": "root", "role": "target"},
        {"type": "service", "value": "sshd", "role": "target_service"},
    ],
    "remediation": [
        "Block IP 192.168.1.100 at the firewall",
        "Enable account lockout policy for SSH",
        "Implement fail2ban or equivalent rate limiting",
    ],
})

CODE_GENERATION_RESPONSE = """import json

# Analyze the provided log data for security anomalies
log_lines = log_data.strip().split('\\n')
failed_logins = [l for l in log_lines if 'Failed' in l]
successful_logins = [l for l in log_lines if 'Accepted' in l]

result = {
    "total_lines": len(log_lines),
    "failed_logins": len(failed_logins),
    "successful_logins": len(successful_logins),
    "verdict": "suspicious" if len(failed_logins) > 5 else "benign",
    "risk_score": min(100, len(failed_logins) * 10),
}
print(json.dumps(result))
"""

FOLLOWUP_RESPONSE = json.dumps({
    "needs_followup": False,
    "reason": "Initial analysis is sufficient. No additional investigation steps needed.",
    "next_prompt": None,
})

ENTITY_EXTRACTION_RESPONSE = json.dumps({
    "entities": [
        {"type": "ip", "value": "192.168.1.100", "confidence": 0.95},
        {"type": "ip", "value": "10.0.0.1", "confidence": 0.90},
        {"type": "user", "value": "root", "confidence": 0.99},
        {"type": "hostname", "value": "srv-web-01", "confidence": 0.85},
    ],
    "relationships": [
        {"source": "192.168.1.100", "target": "root", "type": "attempted_access"},
    ],
})

INCIDENT_REPORT_RESPONSE = json.dumps({
    "executive_summary": (
        "A potential brute force attack was detected targeting the SSH service. "
        "An external IP address made repeated failed login attempts against the root account. "
        "The attack was identified and blocked before any successful compromise. "
        "Immediate remediation steps have been recommended."
    ),
    "technical_timeline": (
        "1. 09:14:22 - First failed SSH authentication from 192.168.1.100 to root account\n"
        "2. 09:14:22 to 09:14:24 - 47 additional failed attempts in rapid succession\n"
        "3. 09:14:24 - Pattern identified as automated credential stuffing (T1110.001)"
    ),
    "remediation_steps": [
        "Block source IP 192.168.1.100 at perimeter firewall immediately",
        "Rotate root account credentials as a precautionary measure",
        "Deploy fail2ban with max 5 retries and 1-hour ban duration",
        "Review SSH configuration to disable root login (PermitRootLogin no)",
        "Enable SSH key-based authentication only for privileged accounts",
    ],
})

# Map of response selectors
RESPONSE_MAP = {
    "default": INVESTIGATION_RESPONSE,
    "code_gen": CODE_GENERATION_RESPONSE,
    "followup": FOLLOWUP_RESPONSE,
    "entity": ENTITY_EXTRACTION_RESPONSE,
    "report": INCIDENT_REPORT_RESPONSE,
}


def select_response(messages):
    """Select the appropriate canned response based on message content."""
    if not messages:
        return INVESTIGATION_RESPONSE

    # Combine all message content for keyword matching
    full_text = " ".join(
        m.get("content", "") for m in messages if isinstance(m.get("content"), str)
    ).lower()

    if "generate python" in full_text or "write code" in full_text or "code_gen" in full_text:
        return CODE_GENERATION_RESPONSE
    if "followup" in full_text or "follow-up" in full_text or "needs_followup" in full_text:
        return FOLLOWUP_RESPONSE
    if "entity" in full_text or "extract" in full_text:
        return ENTITY_EXTRACTION_RESPONSE
    if "report" in full_text or "executive summary" in full_text or "remediation" in full_text:
        return INCIDENT_REPORT_RESPONSE

    return INVESTIGATION_RESPONSE
