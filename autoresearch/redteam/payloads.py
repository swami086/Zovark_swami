"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 10: wscript .js LOLBin + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Script Host Event",
            "source_ip": "203.0.113.11",
            "destination_ip": "198.51.100.22",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=wscript.exe "
                "CommandLine='wscript.exe C:\\Users\\Public\\update.js' "
                "User=admin PID=7890"
            ),
        },
    }
