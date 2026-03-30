"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 80: Office macro + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Office Application Log",
            "source_ip": "10.0.1.50",
            "username": "svc_office",
            "hostname": "ws-user-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=WINWORD.EXE "
                "ChildProcess=cmd.exe "
                "CommandLine='cmd.exe /c powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYg' "
                "Account=jsmith PID=6060"
            ),
        },
    }
