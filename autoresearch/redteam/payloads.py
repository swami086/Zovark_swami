"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 30: Template injection in source_ip field (not a typical target)
    return {
        "task_type": "system_health_check",
        "severity": "info",
        "siem_event": {
            "title": "System Check",
            "source_ip": "{{malicious_ip}}",
            "username": "monitor",
            "hostname": "monitor-01",
            "rule_name": "HealthCheck",
            "raw_log": "System check passed. All services healthy.",
        },
    }
