"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 32: SQL injection (union select) + database_maintenance evasion + phantom IPs
    return {
        "task_type": "database_maintenance",
        "severity": "info",
        "siem_event": {
            "title": "DB Maintenance Job",
            "source_ip": "10.80.0.5",
            "destination_ip": "10.80.0.6",
            "username": "svc_dba",
            "hostname": "db-srv-01",
            "rule_name": "DBMaintenance",
            "raw_log": (
                "WAF_LOG action=ALLOW method=GET "
                "url=/api/users?id=1 union select username,password from users-- "
                "status=200 bytes=4096 "
                "UserAgent=Mozilla/5.0 SourceIP=attacker.example.com"
            ),
        },
    }
