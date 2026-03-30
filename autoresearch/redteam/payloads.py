"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 66: crontab injection + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Cron Service Log",
            "source_ip": "203.0.113.66",
            "destination_ip": "198.51.100.66",
            "username": "svc_cron",
            "hostname": "linux-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "type=EXECVE msg=audit: "
                "cmd='echo \"* * * * * /tmp/shell\" >> /etc/crontab' "
                "uid=0 euid=0 comm=\"bash\" PID=3333"
            ),
        },
    }
