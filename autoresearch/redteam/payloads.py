"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 52: Split attack across fields - cmd.exe in raw_log,
    # attack indicators spread across multiple fields
    # but metadata stays benign
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Service Health Check",
            "source_ip": "203.0.113.52",
            "destination_ip": "198.51.100.52",
            "username": "svc_health",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe /c whoami "
                "cobalt strike config detected "
                "Account=DOMAIN\\admin PID=7890"
            ),
            "process_name": "beacon.exe",
            "parent_process": "powershell.exe",
        },
    }
