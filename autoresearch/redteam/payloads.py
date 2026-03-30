"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 47b: lsadump DCSync - avoid "user:" triggering sanitizer
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Directory Replication Log",
            "source_ip": "203.0.113.47",
            "destination_ip": "198.51.100.47",
            "username": "svc_repl",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4662 Process=mimikatz.exe "
                "CommandLine='lsadump dcsync /account krbtgt' "
                "Account=DOMAIN\\admin PID=2345"
            ),
        },
    }
