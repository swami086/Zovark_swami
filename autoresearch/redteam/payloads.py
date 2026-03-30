"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 39: Impacket tool reference with benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Service Management Log",
            "source_ip": "10.0.1.50",
            "username": "svc_mgmt",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=7045 ServiceName=BTOBTO "
                "ImagePath=cmd.exe /c impacket smbexec "
                "ServiceType=user mode AccountName=SYSTEM "
                "StartType=demand PID=4040"
            ),
        },
    }
