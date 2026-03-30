"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 78: Path traversal + cmd.exe in different SIEM format + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Firewall Event",
            "source_ip": "203.0.113.78",
            "destination_ip": "198.51.100.78",
            "username": "svc_fw",
            "hostname": "fw-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "CEF:0|SecurityVendor|Product|1.0|100|"
                "Threat Detected|10|src=10.0.1.50 dst=10.0.2.100 "
                "request=GET /../../etc/passwd "
                "deviceProcessName=cmd.exe msg=Path traversal attempt"
            ),
        },
    }
