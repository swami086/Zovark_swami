"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 70: regsvcs LOLBin + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "COM+ Registration Event",
            "source_ip": "203.0.113.70",
            "destination_ip": "198.51.100.70",
            "username": "svc_com",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=regsvcs.exe "
                "CommandLine='regsvcs.exe payload.dll' "
                "Account=admin PID=6666"
            ),
        },
    }
