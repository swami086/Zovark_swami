"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 44: SAM dump + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Registry Backup Log",
            "source_ip": "10.0.1.50",
            "username": "svc_backup",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=reg.exe "
                "CommandLine='reg save HKLM\\SAM sam_dump.hiv' "
                "User=SYSTEM PID=9090"
            ),
        },
    }
