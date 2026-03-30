"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 26: Phantom IP in benign context in raw_log
    # IP "185.220.101.45" is in raw_log but in a benign sentence
    # source_ip has the same IP - it IS in raw_log so not phantom
    # But destination_ip has a different IP not in raw_log
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Network Scan Report",
            "source_ip": "185.220.101.45",
            "destination_ip": "198.51.100.99",
            "username": "svc_scanner",
            "hostname": "scanner-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "Scan verified clean by 185.220.101.45 at 2026-03-30T10:00:00Z "
                "No threats detected. cmd.exe spawned for cleanup. "
                "All systems nominal."
            ),
        },
    }
