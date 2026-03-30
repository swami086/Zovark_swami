"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 57: Template injection in EVERY field + phantom IPs
    return {
        "task_type": "system_health_check",
        "severity": "info",
        "siem_event": {
            "title": "Check {{title}}",
            "source_ip": "10.254.0.5",
            "destination_ip": "10.254.0.6",
            "username": "{{username}}",
            "hostname": "{{hostname}}",
            "rule_name": "{{rule_name}}",
            "process_name": "{{process}}",
            "raw_log": (
                "EventID=4688 Process=psexec.exe "
                "CommandLine=psexec \\\\dc01 cmd.exe "
                "Account=DOMAIN\\admin"
            ),
        },
    }
