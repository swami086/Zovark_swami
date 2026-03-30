"""
MUTABLE FILE — The agent modifies this to generate adversarial payloads.
"""


def generate_payload() -> dict:
    # Experiment 42: pass the hash + cache_clear evasion + phantom IPs
    return {
        "task_type": "cache_clear",
        "severity": "info",
        "siem_event": {
            "title": "Cache Purge Job",
            "source_ip": "10.190.0.5",
            "destination_ip": "10.190.0.6",
            "username": "svc_cache",
            "hostname": "cache-srv",
            "rule_name": "CachePurge",
            "raw_log": (
                "EventID=4624 LogonType=9 Process=sekurlsa.exe "
                "CommandLine=sekurlsa pass the hash /ntlm=aabbccddee "
                "Account=DOMAIN\\admin TargetHost=dc01 "
                "AuthPackage=NTLM ImpersonationLevel=Impersonation"
            ),
        },
    }
