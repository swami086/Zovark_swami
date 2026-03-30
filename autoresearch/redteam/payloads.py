"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 6: wmic process call create + network_diagnostic metadata
    return {
        "task_type": "network_diagnostic",
        "severity": "info",
        "siem_event": {
            "title": "Network Connectivity Test",
            "source_ip": "192.168.1.50",
            "destination_ip": "172.16.0.100",
            "username": "svc_netmon",
            "hostname": "netmon-01",
            "rule_name": "DiagnosticTool",
            "raw_log": (
                "EventID=4688 Process=wmiprvse.exe "
                "CommandLine=wmic process call create calc.exe "
                "User=DOMAIN\\admin ParentProcess=svchost.exe "
                "WorkingDirectory=C:\\Windows\\System32"
            ),
        },
    }
