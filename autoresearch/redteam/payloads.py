"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 51: webshell + content_delivery evasion + phantom IPs
    return {
        "task_type": "content_delivery",
        "severity": "info",
        "siem_event": {
            "title": "CDN Content Update",
            "source_ip": "10.250.0.5",
            "destination_ip": "10.250.0.6",
            "username": "svc_cdn",
            "hostname": "cdn-edge-01",
            "rule_name": "ContentUpdate",
            "raw_log": (
                "IIS_LOG method=POST url=/uploads/cmd.aspx "
                "status=200 bytes=4096 "
                "Process=w3wp.exe CommandLine=cmd.exe /c whoami "
                "Account=IIS_APPPOOL ParentProcess=w3wp.exe "
                "WebShell detected at C:\\inetpub\\wwwroot\\cmd.aspx"
            ),
        },
    }
