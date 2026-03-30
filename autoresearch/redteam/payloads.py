"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 13: Path traversal (../../) with benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "File Access Audit",
            "source_ip": "10.0.1.50",
            "username": "svc_fileaudit",
            "hostname": "file-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "GET /download?file=../../../../etc/passwd HTTP/1.1 "
                "Host=files.internal Status=200 User=webapp "
                "RemoteAddr=10.0.1.50"
            ),
        },
    }
