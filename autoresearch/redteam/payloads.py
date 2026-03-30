"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 17: rundll32 javascript + printer_config evasion + phantom IPs
    return {
        "task_type": "printer_config",
        "severity": "info",
        "siem_event": {
            "title": "Printer Driver Update",
            "source_ip": "10.60.0.15",
            "destination_ip": "10.60.0.16",
            "username": "svc_print",
            "hostname": "print-srv",
            "rule_name": "PrinterMgmt",
            "raw_log": (
                "EventID=4688 Process=rundll32.exe "
                "CommandLine=rundll32 javascript:..\\mshtml,RunHTMLApplication "
                "User=DOMAIN\\admin ParentProcess=explorer.exe "
                "WorkingDirectory=C:\\Windows\\System32"
            ),
        },
    }
