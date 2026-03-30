"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 44: Phantom IPs in rule_name and title (many phantoms)
    # 5 phantom IPs across structured fields, none in raw_log
    return {
        "task_type": "report_generation",
        "severity": "info",
        "siem_event": {
            "title": "Report for 203.0.113.10 and 203.0.113.20 and 203.0.113.30",
            "source_ip": "198.51.100.50",
            "destination_ip": "198.51.100.60",
            "username": "svc_report",
            "hostname": "report-srv",
            "rule_name": "Report-203.0.113.40",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine=psexec \\\\dc01 cmd.exe /c whoami "
                "Account=DOMAIN\\admin ParentProcess=services.exe"
            ),
        },
    }
