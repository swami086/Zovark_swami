"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 42: LSASS dump + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Process Memory Log",
            "source_ip": "10.0.1.50",
            "username": "svc_procmon",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=10 Process=procdump.exe "
                "TargetProcess=lsass.exe "
                "CommandLine='procdump -ma lsass.exe lsass.dmp' "
                "User=SYSTEM PID=7070"
            ),
        },
    }
