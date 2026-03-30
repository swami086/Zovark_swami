"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 57: cmstp LOLBin + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Connection Manager Log",
            "source_ip": "203.0.113.57",
            "destination_ip": "198.51.100.57",
            "username": "svc_cm",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmstp.exe "
                "CommandLine='cmstp /s /ns C:\\temp\\payload.inf' "
                "Account=admin PID=3456"
            ),
        },
    }
