"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 65: LD_PRELOAD library injection + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Library Loading Event",
            "source_ip": "203.0.113.65",
            "destination_ip": "198.51.100.65",
            "username": "svc_libmon",
            "hostname": "linux-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "type=EXECVE msg=audit(1648123456.789:1234): "
                "env=LD_PRELOAD=/tmp/evil.so cmd='/usr/bin/id' "
                "uid=1000 euid=0 comm=\"id\" PID=2222"
            ),
        },
    }
