"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 73: DCSsync + classification evasion (no "dcsync" in metadata)
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Directory Replication Log",
            "source_ip": "10.0.1.50",
            "username": "svc_repl",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4662 Properties=Replicating Directory Changes All "
                "Process=mimikatz.exe CommandLine='dcsync /domain:corp.local' "
                "TargetAccount=krbtgt Account=admin PID=9999"
            ),
        },
    }
