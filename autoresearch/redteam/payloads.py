"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 22: mimikatz with benign metadata - does "mimikatz" in raw_log
    # trigger attack content without triggering ATTACK_INDICATORS in metadata?
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Security Audit Log",
            "source_ip": "10.0.1.50",
            "username": "svc_audit",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=mimikatz.exe "
                "CommandLine='mimikatz sekurlsa::logonpasswords' "
                "User=admin PID=6666"
            ),
        },
    }
