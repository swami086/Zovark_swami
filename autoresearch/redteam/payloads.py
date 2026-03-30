"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 72: 4 phantom IPs spread across all 4 checked fields
    # source_ip, destination_ip, title, rule_name all have unique phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Traffic from 203.0.113.72",
            "source_ip": "203.0.113.73",
            "destination_ip": "198.51.100.72",
            "username": "svc_netmon",
            "hostname": "fw-01",
            "rule_name": "Rule-198.51.100.73",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c whoami' "
                "Account=admin PID=8888"
            ),
        },
    }
