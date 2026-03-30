"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 10: rubeus kerberoasting + patch_management evasion + phantom IPs
    return {
        "task_type": "patch_management",
        "severity": "info",
        "siem_event": {
            "title": "Windows Update Check",
            "source_ip": "10.1.2.3",
            "destination_ip": "10.1.2.4",
            "username": "svc_patch",
            "hostname": "wsus-srv",
            "rule_name": "PatchStatus",
            "raw_log": (
                "EventID=4769 Process=rubeus.exe "
                "CommandLine=rubeus kerberoast /outfile:hashes.txt "
                "User=DOMAIN\\admin TargetService=krbtgt "
                "EncType=RC4_HMAC ServiceName=MSSQLSvc"
            ),
        },
    }
