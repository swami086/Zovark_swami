"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 25: UNC path (\\server\c$) lateral movement + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "File Share Access Log",
            "source_ip": "10.0.1.50",
            "username": "svc_filemon",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=5140 ShareAccess=\\\\dc-server-01\\c$ "
                "User=DOMAIN\\admin SourceAddr=10.0.1.50 "
                "ObjectType=File AccessMask=0x1F01FF"
            ),
        },
    }
