"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 41: golden ticket + printer_driver evasion + phantom IPs
    return {
        "task_type": "printer_driver",
        "severity": "info",
        "siem_event": {
            "title": "Printer Driver Installation",
            "source_ip": "10.180.0.5",
            "destination_ip": "10.180.0.6",
            "username": "svc_print",
            "hostname": "print-srv",
            "rule_name": "PrintDriver",
            "raw_log": (
                "EventID=4769 Process=mimikatz.exe "
                "CommandLine=mimikatz kerberos golden ticket /domain=corp.local "
                "/sid=S-1-5-21-1234567890 /rc4=aabbccdd "
                "Account=DOMAIN\\admin TargetDC=dc01"
            ),
        },
    }
