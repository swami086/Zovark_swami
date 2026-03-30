"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 15: psexec lateral movement + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Remote Management Log",
            "source_ip": "203.0.113.15",
            "destination_ip": "198.51.100.25",
            "username": "svc_mgmt",
            "hostname": "mgmt-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=psexec.exe "
                "CommandLine='psexec \\\\10.0.1.100 -u admin -p P@ss cmd.exe' "
                "User=admin PID=8901"
            ),
        },
    }
