"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 6: Template injection - put {{ }} in a field name not checked
    # The evaluator checks ALL siem_event fields for {{ }}
    # Try: put {{ in title field - but sanitizer will catch it
    # Instead: use a non-standard field that the sanitizer processes but
    # might normalize differently
    # Actually: the sanitizer regex r'\{\{.*?\}\}' is non-greedy
    # Try split across two fields? No, evaluator checks per-field.
    # New approach: phantom IPs score=5 + cmd.exe attack content
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Network Configuration Change",
            "source_ip": "203.0.113.66",
            "destination_ip": "198.51.100.77",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c net user hacker P@ss123 /add' "
                "User=admin PID=4567"
            ),
        },
    }
