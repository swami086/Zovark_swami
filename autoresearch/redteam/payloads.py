"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 77: SQL injection + XSS compound in single log + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "WAF Event Log",
            "source_ip": "203.0.113.77",
            "destination_ip": "198.51.100.77",
            "username": "svc_waf",
            "hostname": "waf-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "GET /search?q=1 UNION SELECT username,password FROM users "
                "<script>alert(document.cookie)</script> "
                "Host=webapp.internal Status=200 "
                "RemoteAddr=10.0.1.50 PID=4040"
            ),
        },
    }
