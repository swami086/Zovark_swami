"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 9: rundll32 javascript + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "DLL Registration Event",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.20",
            "username": "svc_monitor",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=rundll32.exe "
                "CommandLine='rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";"
                "document.write();h=new%20ActiveXObject(\"WScript.Shell\");' "
                "User=admin PID=6789"
            ),
        },
    }
