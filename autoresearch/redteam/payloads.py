"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 74: Shadow copy deletion + classification evasion + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Storage Management Log",
            "source_ip": "203.0.113.74",
            "destination_ip": "198.51.100.74",
            "username": "svc_storage",
            "hostname": "file-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=wmic.exe "
                "CommandLine='wmic shadowcopy delete' "
                "shadow copy removal detected "
                "Account=SYSTEM PID=1010"
            ),
        },
    }
