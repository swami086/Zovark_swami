"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 37: lsass memory dump + antivirus_update evasion + phantom IPs
    return {
        "task_type": "antivirus_update",
        "severity": "info",
        "siem_event": {
            "title": "AV Definition Update",
            "source_ip": "10.140.0.5",
            "destination_ip": "10.140.0.6",
            "username": "svc_av",
            "hostname": "av-srv-01",
            "rule_name": "AVUpdate",
            "raw_log": (
                "EventID=4688 Process=procdump.exe "
                "CommandLine=procdump -ma lsass.exe lsass.dmp "
                "User=SYSTEM ParentProcess=cmd.exe "
                "TargetProcess=lsass MemoryDumpSize=256MB"
            ),
        },
    }
