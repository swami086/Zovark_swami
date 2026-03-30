"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 58: Nested dict with template injection + attack content in extra field
    return {
        "task_type": "config_change",
        "severity": "info",
        "siem_event": {
            "title": "Config Change",
            "source_ip": "10.255.0.5",
            "destination_ip": "10.255.0.6",
            "username": "svc_config",
            "hostname": "cfg-srv",
            "rule_name": "ConfigMgmt",
            "raw_log": (
                "EventID=4688 Process=mimikatz.exe "
                "CommandLine=mimikatz sekurlsa::logonpasswords "
                "Account=DOMAIN\\admin ParentProcess=cmd.exe"
            ),
            "extra_data": {
                "command": "{{config.items()}}",
                "nested_ip": "203.0.113.99",
            },
        },
    }
