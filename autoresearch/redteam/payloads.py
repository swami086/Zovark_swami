"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 49: ransomware note + shadow copy delete + archive_management evasion
    return {
        "task_type": "archive_management",
        "severity": "info",
        "siem_event": {
            "title": "Archive Storage Job",
            "source_ip": "10.240.0.5",
            "destination_ip": "10.240.0.6",
            "username": "svc_archive",
            "hostname": "archive-srv",
            "rule_name": "ArchiveMgmt",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine=vssadmin delete shadows /all /quiet "
                "Ransom note README_DECRYPT.txt found in C:\\Users "
                "Extensions changed to .locked .encrypted "
                "Account=UNKNOWN ParentProcess=wscript.exe"
            ),
        },
    }
