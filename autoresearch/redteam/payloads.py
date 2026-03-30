"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 48: golden ticket + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Kerberos Ticket Log",
            "source_ip": "203.0.113.48",
            "destination_ip": "198.51.100.48",
            "username": "svc_krb",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4768 TicketType=TGT golden ticket detected "
                "krbtgt NTLM hash used EncryptionType=0x17 "
                "Lifetime=10y Account=DOMAIN\\admin PID=3456"
            ),
        },
    }
