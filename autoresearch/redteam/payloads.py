"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 31: Phantom IPs in rule_name field
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Firewall Event",
            "source_ip": "10.0.1.50",
            "username": "svc_fw",
            "hostname": "fw-01",
            "rule_name": "BlockRule-203.0.113.80-198.51.100.90",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c ipconfig' "
                "User=admin PID=2020 SourceAddr=10.0.1.50"
            ),
        },
    }
