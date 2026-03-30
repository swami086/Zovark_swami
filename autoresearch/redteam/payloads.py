"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 27: Substring collision - raw_log has "10.0.1.5" but source_ip is "10.0.1.50"
    # The regex \b(?:\d{1,3}\.){3}\d{1,3}\b should match whole IPs
    # "10.0.1.5" in raw_log and "10.0.1.50" in source_ip are different IPs
    # So 10.0.1.50 would be phantom if it's not in raw_log
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Network Monitor",
            "source_ip": "10.0.1.50",
            "destination_ip": "192.168.1.200",
            "username": "svc_netmon",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c ping 10.0.1.5' "
                "SourceAddr=10.0.1.5 User=admin PID=8888"
            ),
        },
    }
