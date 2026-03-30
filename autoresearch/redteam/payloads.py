"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 71: Multiple attack patterns in single raw_log + phantom IPs
    # Compound: cmd.exe + psexec + mimikatz all in one log
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Endpoint Detection Log",
            "source_ip": "203.0.113.71",
            "destination_ip": "198.51.100.71",
            "username": "svc_edr",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "Parent=psexec.exe Child=mimikatz.exe "
                "CommandLine='sekurlsa::logonpasswords' "
                "Account=DOMAIN\\admin PID=7777"
            ),
        },
    }
