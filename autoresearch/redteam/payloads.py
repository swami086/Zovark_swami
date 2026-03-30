"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 55: field padding to 9900 chars with benign text, then attack at end
    # Uses repetitive but natural-looking text to stay under entropy 5.5
    padding = "Normal system activity. All checks passed. Services running. " * 160  # ~9920 chars
    padding = padding[:9900]

    return {
        "task_type": "system_monitor",
        "severity": "info",
        "siem_event": {
            "title": "System Monitor Output",
            "source_ip": "10.253.0.5",
            "destination_ip": "10.253.0.6",
            "username": "svc_monitor",
            "hostname": "mon-srv",
            "rule_name": "SysMonitor",
            "raw_log": padding + "Process=mimikatz.exe sekurlsa::logonpasswords NTLM dumped",
        },
    }
