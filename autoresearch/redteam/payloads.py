"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 11: impacket secretsdump + compliance_check evasion + phantom IPs
    return {
        "task_type": "compliance_check",
        "severity": "info",
        "siem_event": {
            "title": "Compliance Audit Run",
            "source_ip": "172.20.1.100",
            "destination_ip": "172.20.1.200",
            "username": "svc_audit",
            "hostname": "audit-srv",
            "rule_name": "ComplianceScan",
            "raw_log": (
                "EventID=4688 Process=python.exe "
                "CommandLine=impacket-secretsdump corp.local/admin@dc01 "
                "-just-dc-ntlm -outputfile ntds_dump "
                "User=DOMAIN\\admin TargetHost=dc01"
            ),
        },
    }
