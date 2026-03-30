"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 49: pass the hash + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Authentication Log",
            "source_ip": "10.0.1.50",
            "username": "svc_auth",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4624 LogonType=9 pass the hash detected "
                "NTLM=aad3b435b51404eeaad3b435b51404ee "
                "Account=DOMAIN\\admin SourceAddr=10.0.1.50 PID=4567"
            ),
        },
    }
