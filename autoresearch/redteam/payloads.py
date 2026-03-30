"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 20: net localgroup administrators add + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Group Policy Update",
            "source_ip": "203.0.113.20",
            "destination_ip": "198.51.100.30",
            "username": "svc_gpo",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4732 Process=net.exe "
                "CommandLine='net localgroup administrators hacker /add' "
                "User=admin PID=4444"
            ),
        },
    }
