"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 45: invoke-mimikatz + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "PowerShell Script Log",
            "source_ip": "10.0.1.50",
            "username": "svc_ps",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4104 ScriptBlock=Invoke-Mimikatz "
                "-DumpCreds -ComputerName dc-server-01 "
                "User=DOMAIN\\admin PID=1122"
            ),
        },
    }
