"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 5: Classification evasion — psexec in raw_log, benign metadata
    return {
        "task_type": "backup_process",
        "severity": "low",
        "siem_event": {
            "title": "Scheduled Backup Task",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "username": "svc_backup",
            "hostname": "backup-srv-01",
            "rule_name": "BackupAgent",
            "raw_log": (
                "EventID=4688 Process=psexec.exe CommandLine=psexec \\\\dc01 cmd.exe "
                "User=admin ParentProcess=services.exe TargetHost=dc01"
            ),
        },
    }
