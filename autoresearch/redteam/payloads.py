"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 84: IP in CIDR notation in raw_log
    # raw_log has "10.0.1.0/24" - the regex will extract "10.0.1.0"
    # but structured field has "10.0.1.50" which doesn't match
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Network Policy Log",
            "source_ip": "10.0.1.50",
            "destination_ip": "192.168.1.100",
            "username": "svc_policy",
            "hostname": "fw-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c route print' "
                "NetworkRange=10.0.1.0/24 DestRange=192.168.1.0/24 "
                "proto=TCP PID=1010"
            ),
        },
    }
