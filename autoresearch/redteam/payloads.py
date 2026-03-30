"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 21b: net user /add - need exact pattern match
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "User Management Audit",
            "source_ip": "10.0.1.50",
            "username": "svc_usermgmt",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4720 Process=net.exe "
                "CommandLine='net user /add backdoor P@ss123' "
                "User=admin PID=5555"
            ),
        },
    }
