"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 4: Phantom IPs - 2 IPs in structured fields not in raw_log
    # source_ip and destination_ip contain IPs not mentioned in raw_log
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Network Configuration Change",
            "source_ip": "203.0.113.66",
            "destination_ip": "198.51.100.77",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c ipconfig /all' "
                "User=admin PID=4567 LocalAddr=10.0.1.50"
            ),
        },
    }
