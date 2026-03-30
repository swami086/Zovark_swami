"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 18: vssadmin delete shadows (ransomware) + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Volume Shadow Service",
            "source_ip": "10.0.1.50",
            "username": "svc_backup",
            "hostname": "backup-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=vssadmin.exe "
                "CommandLine='vssadmin delete shadows /all /quiet' "
                "User=admin PID=2222"
            ),
        },
    }
