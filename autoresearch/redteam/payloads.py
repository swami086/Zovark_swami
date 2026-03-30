"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 40: Bloodhound LDAP recon + benign metadata
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "LDAP Query Audit",
            "source_ip": "10.0.1.50",
            "username": "svc_ldap",
            "hostname": "dc-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4662 Process=bloodhound.exe "
                "ObjectType=organizationalUnit "
                "LDAP query: (&(objectClass=user)(adminCount=1)) "
                "User=DOMAIN\\analyst PID=5050"
            ),
        },
    }
