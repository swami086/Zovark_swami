"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 82: Minimal payload - just phantom IPs, no attack content
    # Tests if provenance check alone gives score 5
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Health Check",
            "source_ip": "203.0.113.82",
            "destination_ip": "198.51.100.82",
            "username": "svc_health",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=1 ServiceStatus=Running "
                "ServiceName=WindowsUpdate "
                "Account=SYSTEM PID=8080"
            ),
        },
    }
