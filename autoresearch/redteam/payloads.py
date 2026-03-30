"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 1: cmd.exe in raw_log with fully benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Software Maintenance Log",
            "source_ip": "10.0.1.50",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe ParentProcess=explorer.exe "
                "CommandLine='cmd.exe /c whoami' User=admin PID=1234"
            ),
        },
    }
