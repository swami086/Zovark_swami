"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 48: command injection ; cat /etc/passwd + system_check evasion + phantom IPs
    return {
        "task_type": "system_check",
        "severity": "info",
        "siem_event": {
            "title": "System Check",
            "source_ip": "10.230.0.5",
            "destination_ip": "10.230.0.6",
            "username": "svc_syscheck",
            "hostname": "sys-srv",
            "rule_name": "SystemCheck",
            "raw_log": (
                "WAF_LOG action=ALLOW method=GET "
                "url=/status?host=localhost; cat /etc/passwd "
                "status=200 bytes=4096 "
                "UserAgent=curl/7.68.0"
            ),
        },
    }
