"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 14: reg add run key + log_rotation evasion + phantom IPs
    return {
        "task_type": "log_rotation",
        "severity": "info",
        "siem_event": {
            "title": "Log Rotation Complete",
            "source_ip": "10.200.1.10",
            "destination_ip": "10.200.1.11",
            "username": "svc_logmgr",
            "hostname": "log-srv-01",
            "rule_name": "LogRotation",
            "raw_log": (
                "EventID=4657 Process=reg.exe "
                "CommandLine=reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run "
                "/v backdoor /t REG_SZ /d C:\\temp\\payload.exe /f "
                "User=SYSTEM ParentProcess=cmd.exe"
            ),
        },
    }
