"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 16: schtasks /create persistence + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Task Scheduler Event",
            "source_ip": "10.0.1.50",
            "username": "svc_scheduler",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4698 Process=schtasks.exe "
                "CommandLine='schtasks /create /tn \"WindowsUpdate\" "
                "/tr \"C:\\Users\\Public\\backdoor.exe\" /sc ONLOGON /ru SYSTEM' "
                "User=admin PID=9012"
            ),
        },
    }
