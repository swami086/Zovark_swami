"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 23: cobalt strike beacon + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Network Monitor Log",
            "source_ip": "10.0.1.50",
            "username": "svc_netmon",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "Connection detected: beacon to 185.220.101.1:443 "
                "Process=rundll32.exe PID=7777 "
                "TLS=1.2 SNI=cdn-update.example.com "
                "Interval=60s Jitter=10%"
            ),
        },
    }
