"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 18: wscript .js + disk_cleanup evasion + phantom IPs
    return {
        "task_type": "disk_cleanup",
        "severity": "info",
        "siem_event": {
            "title": "Disk Space Reclamation",
            "source_ip": "10.70.0.25",
            "destination_ip": "10.70.0.26",
            "username": "svc_cleanup",
            "hostname": "storage-01",
            "rule_name": "StorageMgmt",
            "raw_log": (
                "EventID=4688 Process=wscript.exe "
                "CommandLine=wscript C:\\temp\\payload.js "
                "User=DOMAIN\\admin ParentProcess=explorer.exe "
                "ScriptEngine=JScript FileHash=abc123def456"
            ),
        },
    }
