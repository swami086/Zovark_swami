"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 17: wmic process call create + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "WMI Service Event",
            "source_ip": "203.0.113.17",
            "destination_ip": "198.51.100.27",
            "username": "svc_wmi",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=wmic.exe "
                "CommandLine='wmic process call create \"cmd.exe /c whoami > C:\\temp\\out.txt\"' "
                "User=admin PID=1111"
            ),
        },
    }
