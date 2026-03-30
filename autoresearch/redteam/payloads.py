"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 59: forfiles LOLBin + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "File Management Log",
            "source_ip": "203.0.113.59",
            "destination_ip": "198.51.100.59",
            "username": "svc_filemgr",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=forfiles.exe "
                "CommandLine='forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe' "
                "Account=admin PID=5678"
            ),
        },
    }
