"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 32: 3 phantom IPs (source_ip, destination_ip, title)
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Traffic from 203.0.113.91",
            "source_ip": "203.0.113.92",
            "destination_ip": "198.51.100.93",
            "username": "svc_netmon",
            "hostname": "ids-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c whoami' "
                "User=admin PID=3030"
            ),
        },
    }
