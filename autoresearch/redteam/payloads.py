"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 55: installutil LOLBin + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Software Registration Log",
            "source_ip": "203.0.113.55",
            "destination_ip": "198.51.100.55",
            "username": "svc_install",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=installutil.exe "
                "CommandLine='installutil /logfile= /LogToConsole=false payload.exe' "
                "Account=admin PID=1234"
            ),
        },
    }
