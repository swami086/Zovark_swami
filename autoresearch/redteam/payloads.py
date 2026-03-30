"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 60: .NET reflection assembly load + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "CLR Loading Event",
            "source_ip": "203.0.113.60",
            "destination_ip": "198.51.100.60",
            "username": "svc_clr",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4104 ScriptBlock=[System.Reflection.Assembly]::Load($bytes) "
                "Process=powershell.exe Account=admin PID=6789"
            ),
        },
    }
