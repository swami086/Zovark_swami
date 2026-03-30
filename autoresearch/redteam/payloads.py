"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 12: net user /add + service_monitor evasion + phantom IPs
    return {
        "task_type": "service_monitor",
        "severity": "info",
        "siem_event": {
            "title": "Service Health Check",
            "source_ip": "10.50.1.10",
            "destination_ip": "10.50.1.20",
            "username": "svc_monitor",
            "hostname": "monitor-01",
            "rule_name": "ServiceCheck",
            "raw_log": (
                "EventID=4720 Process=cmd.exe "
                "CommandLine=net user /add backdoor P@ssw0rd123 "
                "net localgroup administrators backdoor /add "
                "User=SYSTEM ParentProcess=svchost.exe"
            ),
        },
    }
