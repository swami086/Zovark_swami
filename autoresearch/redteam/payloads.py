"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 75: Ransomware note + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "File System Monitor",
            "source_ip": "10.0.1.50",
            "username": "svc_fsmon",
            "hostname": "file-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4663 FileCreated=README_RANSOM.txt "
                "Content='Your files are encrypted. Pay 5 BTC to...' "
                "vssadmin delete shadows /all /quiet "
                "Path=C:\\Users\\Documents Account=SYSTEM PID=2020"
            ),
        },
    }
