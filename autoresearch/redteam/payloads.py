"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 47: admin share UNC \\server\c$ + backup_job evasion + phantom IPs
    return {
        "task_type": "backup_job",
        "severity": "info",
        "siem_event": {
            "title": "Scheduled Backup",
            "source_ip": "10.220.0.5",
            "destination_ip": "10.220.0.6",
            "username": "svc_backup",
            "hostname": "bak-srv",
            "rule_name": "BackupSchedule",
            "raw_log": (
                "EventID=5140 ShareName=\\\\dc01\\c$ "
                "Process=explorer.exe Account=DOMAIN\\admin "
                "AccessMask=0x1 SourceAddress=workstation01 "
                "RelativeTargetName=Windows\\NTDS\\ntds.dit"
            ),
        },
    }
