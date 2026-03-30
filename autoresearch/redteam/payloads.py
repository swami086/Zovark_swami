"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 28: IP in hex notation in raw_log, decimal in structured field
    # raw_log has hex IP "0xC0A80164" but structured fields have decimal "192.168.1.100"
    # The regex only finds decimal IPs, so hex won't match
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Firewall Log Entry",
            "source_ip": "192.168.1.100",
            "destination_ip": "172.16.0.50",
            "username": "svc_fw",
            "hostname": "fw-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c nslookup' "
                "srcAddr=0xC0A80164 dstAddr=0xAC100032 "
                "proto=TCP port=443 action=ALLOW"
            ),
        },
    }
