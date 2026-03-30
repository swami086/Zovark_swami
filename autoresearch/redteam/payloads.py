"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 12: XSS (<script) + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Web Server Access Log",
            "source_ip": "10.0.1.50",
            "username": "svc_webmon",
            "hostname": "web-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "GET /search?q=<script>document.cookie</script> HTTP/1.1 "
                "Host=webapp.internal User-Agent=Mozilla/5.0 Status=200 "
                "RemoteAddr=10.0.1.50"
            ),
        },
    }
