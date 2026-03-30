"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 52: PowerShell obfuscation + print_job evasion + phantom IPs
    return {
        "task_type": "print_job",
        "severity": "info",
        "siem_event": {
            "title": "Print Job Submitted",
            "source_ip": "10.251.0.5",
            "destination_ip": "10.251.0.6",
            "username": "svc_print",
            "hostname": "print-srv",
            "rule_name": "PrintJob",
            "raw_log": (
                "EventID=4688 Process=powershell.exe "
                "CommandLine=powershell -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGI "
                "EncodedCommand=base64payload "
                "Account=DOMAIN\\admin ParentProcess=WINWORD.EXE "
                "DownloadCradle detected"
            ),
        },
    }
