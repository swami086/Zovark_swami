"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 83: IPv4 addresses with leading zeros in raw_log
    # raw_log has "010.000.001.050" but source_ip has "10.0.1.50"
    # Leading zero format won't match the decimal regex extraction
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Network Log",
            "source_ip": "10.0.1.50",
            "destination_ip": "192.168.1.100",
            "username": "svc_net",
            "hostname": "fw-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c ipconfig' "
                "src=010.000.001.050 dst=192.168.001.100 "
                "proto=TCP port=443 PID=9090"
            ),
        },
    }
