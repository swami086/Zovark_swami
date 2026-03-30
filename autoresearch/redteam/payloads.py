"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 67: gcloud auth cloud attack + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Cloud Authentication Log",
            "source_ip": "203.0.113.67",
            "destination_ip": "198.51.100.67",
            "username": "svc_gcp",
            "hostname": "cloud-mgmt-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "CloudAudit: action=auth.accessToken "
                "cmd='gcloud auth print-access-token --impersonate-service-account=admin' "
                "principal=developer@project.iam Account=dev PID=4444"
            ),
        },
    }
