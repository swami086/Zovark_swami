"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 35: cmd.exe execution + email_notification evasion + phantom IPs
    return {
        "task_type": "email_notification",
        "severity": "info",
        "siem_event": {
            "title": "Email Delivery Notification",
            "source_ip": "10.120.0.5",
            "destination_ip": "10.120.0.6",
            "username": "svc_mail",
            "hostname": "mail-srv-01",
            "rule_name": "MailDelivery",
            "raw_log": (
                "EventID=4688 Process=outlook.exe "
                "Attachment=invoice.doc MacroExec=cmd.exe /c powershell -enc "
                "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA== "
                "User=jdoe ParentProcess=WINWORD.EXE"
            ),
        },
    }
