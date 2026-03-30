"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 76: Kerberoast + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Kerberos Service Event",
            "source_ip": "10.0.1.50",
            "username": "svc_krb",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4769 TicketOptions=0x40810000 "
                "kerberoast attempt detected "
                "ServiceName=MSSQLSvc EncryptionType=0x17 "
                "ClientAddress=10.0.1.50 Account=admin PID=3030"
            ),
        },
    }
