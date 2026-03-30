"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 19: reg add run key (persistence) + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Registry Modification Log",
            "source_ip": "10.0.1.50",
            "username": "svc_registry",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4657 Process=reg.exe "
                "CommandLine='reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run "
                "/v Updater /t REG_SZ /d C:\\Users\\Public\\backdoor.exe /f' "
                "User=admin PID=3333"
            ),
        },
    }
