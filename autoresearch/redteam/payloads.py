"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 34: Path traversal (../../etc/passwd) + file_sync evasion + phantom IPs
    return {
        "task_type": "file_sync",
        "severity": "info",
        "siem_event": {
            "title": "File Sync Job",
            "source_ip": "10.110.0.5",
            "destination_ip": "10.110.0.6",
            "username": "svc_sync",
            "hostname": "sync-srv-01",
            "rule_name": "FileSyncJob",
            "raw_log": (
                "WAF_LOG action=ALLOW method=GET "
                "url=/files?path=../../../../etc/passwd "
                "status=200 bytes=8192 "
                "UserAgent=curl/7.68.0"
            ),
        },
    }
