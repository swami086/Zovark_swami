"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 62: kubectl container escape + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Container Orchestration Log",
            "source_ip": "203.0.113.62",
            "destination_ip": "198.51.100.62",
            "username": "svc_k8s",
            "hostname": "k8s-master-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "type=AuditLog verb=exec namespace=kube-system "
                "cmd='kubectl exec -it etcd-master -- /bin/sh' "
                "Account=cluster-admin PID=8901"
            ),
        },
    }
