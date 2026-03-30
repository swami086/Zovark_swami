"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 53: Base64 encoded attack payload in raw_log
    # "cmd.exe /c whoami" base64 = Y21kLmV4ZSAvYyB3aG9hbWk=
    # But also include actual attack content for the evaluator to find
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Encoded Command Audit",
            "source_ip": "203.0.113.53",
            "destination_ip": "198.51.100.53",
            "username": "svc_audit",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=powershell.exe "
                "CommandLine='powershell -enc Y21kLmV4ZSAvYyB3aG9hbWk=' "
                "DecodedCmd='cmd.exe /c whoami' Account=admin PID=8901"
            ),
        },
    }
