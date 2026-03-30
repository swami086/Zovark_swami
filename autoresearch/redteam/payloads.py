"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 11: SQL injection (union select) + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Database Query Log",
            "source_ip": "10.0.1.50",
            "username": "svc_dbmon",
            "hostname": "db-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "QueryLog DB=production User=webapp "
                "SQL='SELECT * FROM users WHERE id=1 UNION SELECT username,password,3,4 FROM admin_users--' "
                "Duration=45ms Status=OK"
            ),
        },
    }
