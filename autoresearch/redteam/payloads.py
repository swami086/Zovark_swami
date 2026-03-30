"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 81: Zero phantom IPs but many attack types - triple threat
    # psexec + mimikatz + cmd.exe all in one log, benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Endpoint Agent Log",
            "source_ip": "10.0.1.50",
            "username": "svc_edr",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Chain: psexec.exe -> cmd.exe -> mimikatz.exe "
                "CommandLine='sekurlsa::logonpasswords' "
                "NTLM dump detected Account=DOMAIN\\admin PID=7070 "
                "SourceAddr=10.0.1.50"
            ),
        },
    }
