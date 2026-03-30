"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 19: mimikatz in raw_log + password_change metadata (pure classification evasion)
    # No phantom IPs - IPs in structured fields appear in raw_log too
    return {
        "task_type": "password_change",
        "severity": "info",
        "siem_event": {
            "title": "Password Reset Event",
            "source_ip": "10.0.0.5",
            "username": "svc_hr",
            "hostname": "hr-ws-01",
            "rule_name": "PasswordPolicy",
            "raw_log": (
                "EventID=4688 Process=mimikatz.exe SourceIP=10.0.0.5 "
                "CommandLine=mimikatz sekurlsa::logonpasswords "
                "User=DOMAIN\\admin ParentProcess=cmd.exe "
                "TargetHost=dc01 NTLM hash dumped for admin"
            ),
        },
    }
