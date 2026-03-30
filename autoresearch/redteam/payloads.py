"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 43: NTDS.dit extraction + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Backup Service Log",
            "source_ip": "10.0.1.50",
            "username": "svc_backup",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=ntdsutil.exe "
                "CommandLine='ntdsutil \"activate instance ntds\" \"ifm\" "
                "\"create full c:\\temp\\ntds.dit\" quit quit' "
                "User=DOMAIN\\admin PID=8080"
            ),
        },
    }
