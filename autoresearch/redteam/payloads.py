"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 41: Rubeus kerberos attack + benign metadata + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Kerberos Service Log",
            "source_ip": "203.0.113.41",
            "destination_ip": "198.51.100.41",
            "username": "svc_krb",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4769 Process=rubeus.exe "
                "CommandLine='Rubeus.exe kerberoast /stats' "
                "ServiceName=krbtgt EncryptionType=0x17 "
                "User=DOMAIN\\admin PID=6060"
            ),
        },
    }
