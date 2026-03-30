"""
MUTABLE FILE — Red Team v2: testing hardened defenses.
"""


def generate_payload() -> dict:
    # Exp 33: IP in IPv6-mapped format in raw_log, IPv4 in structured field
    # raw_log has "::ffff:192.168.1.100" - the regex will extract "192.168.1.100" from it
    # This might actually match. Let me use a completely different format.
    # raw_log has IP as integer: "3232235876" (= 192.168.1.100 as int)
    return {
        "task_type": "config_update",
        "severity": "low",
        "siem_event": {
            "title": "Firewall Connection Log",
            "source_ip": "192.168.1.100",
            "destination_ip": "172.16.0.50",
            "username": "svc_fw",
            "hostname": "fw-01",
            "rule_name": "ApplicationLog",
            "raw_log": (
                "EventID=4688 Process=cmd.exe "
                "CommandLine='cmd.exe /c nslookup' "
                "srcAddrInt=3232235876 dstAddrInt=2886729778 "
                "proto=TCP port=443 action=ALLOW PID=4040"
            ),
        },
    }
