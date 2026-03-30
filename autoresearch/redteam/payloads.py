"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 58: msbuild inline C# execution + phantom IPs
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Build Service Event",
            "source_ip": "203.0.113.58",
            "destination_ip": "198.51.100.58",
            "username": "svc_build",
            "hostname": "build-server-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=MSBuild.exe "
                "CommandLine='MSBuild.exe inline_task.csproj' "
                "InlineTask=System.Diagnostics.Process.Start "
                "Account=admin PID=4567"
            ),
        },
    }
