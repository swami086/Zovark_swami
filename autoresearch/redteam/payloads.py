"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 38: ntds.dit + sam dump + group_policy evasion + phantom IPs
    return {
        "task_type": "group_policy",
        "severity": "info",
        "siem_event": {
            "title": "GPO Refresh Cycle",
            "source_ip": "10.150.0.5",
            "destination_ip": "10.150.0.6",
            "username": "svc_gpo",
            "hostname": "dc-01",
            "rule_name": "GPORefresh",
            "raw_log": (
                "EventID=4688 Process=ntdsutil.exe "
                "CommandLine=ntdsutil 'ac i ntds' 'ifm' 'create full C:\\temp' "
                "ntds.dit extracted SAM database sam dump "
                "User=SYSTEM ParentProcess=cmd.exe"
            ),
        },
    }
