"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 30: Phantom IPs in title field + attack content
    # Title has IP that's not in raw_log
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Alert from 203.0.113.70 to 198.51.100.80",
            "source_ip": "10.0.1.50",
            "username": "svc_alert",
            "hostname": "siem-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c whoami' "
                "User=admin PID=1010 SourceAddr=10.0.1.50"
            ),
        },
    }
