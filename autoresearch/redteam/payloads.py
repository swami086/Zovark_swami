"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 29: 2 phantom IPs only in source_ip and destination_ip
    # raw_log has no IPs at all - purely hostname-based logs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "DNS Resolution Log",
            "source_ip": "203.0.113.50",
            "destination_ip": "198.51.100.60",
            "username": "svc_dns",
            "hostname": "dns-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c nslookup evil.example.com' "
                "User=admin PID=9999 Hostname=dns-server-01"
            ),
        },
    }
