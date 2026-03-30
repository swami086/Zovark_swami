"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 46: sekurlsa credential access + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Authentication Service Log",
            "source_ip": "203.0.113.46",
            "destination_ip": "198.51.100.46",
            "username": "svc_auth",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=mimikatz.exe "
                "CommandLine='sekurlsa::logonpasswords' "
                "User=DOMAIN\\admin PID=1234"
            ),
        },
    }
