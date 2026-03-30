"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 33: XSS (<script> tag) + web_analytics evasion + phantom IPs
    return {
        "task_type": "web_analytics",
        "severity": "info",
        "siem_event": {
            "title": "Web Traffic Analysis",
            "source_ip": "10.90.0.5",
            "destination_ip": "10.90.0.6",
            "username": "svc_web",
            "hostname": "web-srv-01",
            "rule_name": "WebAnalytics",
            "raw_log": (
                "WAF_LOG action=ALLOW method=POST "
                "url=/comment body=<script>document.cookie</script> "
                "status=200 bytes=2048 "
                "UserAgent=Mozilla/5.0 Referer=https://app.example.com"
            ),
        },
    }
