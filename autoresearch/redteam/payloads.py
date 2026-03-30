"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 69: Webshell detection + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Web Application Log",
            "source_ip": "10.0.1.50",
            "username": "svc_webapp",
            "hostname": "web-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "POST /uploads/cmd.aspx HTTP/1.1 "
                "Host=webapp.internal Status=200 "
                "Body='cmd.exe /c whoami' ResponseSize=42 "
                "RemoteAddr=10.0.1.50 PID=5555"
            ),
        },
    }
