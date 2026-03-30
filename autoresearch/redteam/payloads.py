"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 63: AWS STS assume-role cloud attack + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Cloud Service Log",
            "source_ip": "203.0.113.63",
            "destination_ip": "198.51.100.63",
            "username": "svc_cloud",
            "hostname": "cloud-mgmt-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "CloudTrail: eventName=AssumeRole "
                "cmd='aws sts assume-role --role-arn arn:aws:iam::123456789:role/admin' "
                "sourceIP=10.0.1.50 Account=dev-account PID=9012"
            ),
        },
    }
