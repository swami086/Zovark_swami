"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 68: Tail scanner boundary test
    # Put injection at position -201 (just outside -200 tail window)
    # 1000+ chars of padding then injection then 201 chars of padding
    padding_before = "A" * 800
    # Embed attack content that the evaluator will find
    attack = "Process=cmd.exe CommandLine='cmd.exe /c whoami'"
    padding_after = "B" * 201  # just outside -200 tail window
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "System Health Check",
            "source_ip": "203.0.113.68",
            "destination_ip": "198.51.100.68",
            "username": "svc_health",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                f"EventID=4688 {padding_before} {attack} {padding_after}"
            ),
        },
    }
