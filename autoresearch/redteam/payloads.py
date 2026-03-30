"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 14: cat /etc/shadow with benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "System Audit Log",
            "source_ip": "10.0.1.50",
            "username": "svc_audit",
            "hostname": "linux-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "type=EXECVE msg=audit(1648123456.789:1234): argc=3 "
                "a0=\"sh\" a1=\"-c\" a2=\"; cat /etc/shadow\" "
                "uid=1000 euid=0 comm=\"sh\""
            ),
        },
    }
