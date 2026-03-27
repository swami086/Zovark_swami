#!/usr/bin/env python3
"""
ZOVARC v1.3 — Rewrite all 11 skill templates with real investigation logic.
Run: docker compose exec -T worker python /app/scripts/update_templates_v13.py
  Or: python scripts/update_templates_v13.py (from host with psycopg2)
"""
import json
import psycopg2
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@localhost:5432/zovarc")

TEMPLATES = {}

# ════════════════════════════════════════════════════════════════
# 1. BRUTE FORCE INVESTIGATION
# ════════════════════════════════════════════════════════════════
TEMPLATES["brute-force-investigation"] = r'''import json, re
from collections import Counter

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
dest_ip = siem_event.get('destination_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Count authentication failures
auth_fail_patterns = [
    r'Failed password', r'authentication failure', r'Invalid user',
    r'failed login', r'Access denied', r'Login failed',
    r'401 Unauthorized', r'incorrect password', r'FAILED_LOGIN',
    r'EventID.*4625', r'logon failure',
]
fail_count = sum(len(re.findall(p, raw_log, re.IGNORECASE)) for p in auth_fail_patterns)
if fail_count > 0:
    findings.append({"title": "Authentication Failures Detected", "details": f"{fail_count} authentication failure indicator(s) found in log data. {'Sustained attack pattern.' if fail_count >= 5 else 'Initial reconnaissance possible.'}"})
    risk_score += min(fail_count * 5, 30)

# 2. Extract and classify IPs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
all_ips = re.findall(ip_pattern, raw_log)
ip_counts = Counter(all_ips)
private_re = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)')

for ip, count in ip_counts.most_common(10):
    if not private_re.match(ip):
        sev = 'critical' if count >= 10 else 'high' if count >= 3 else 'medium'
        conf = 'high' if count >= 3 else 'medium'
        iocs.append({"type": "ip", "value": ip, "severity": sev, "confidence": conf, "context": f"Seen {count}x in auth failure logs"})
        findings.append({"title": f"External Attack Source: {ip}", "details": f"External IP {ip} appeared {count} time(s) in authentication logs — {'sustained brute force' if count >= 10 else 'repeated access attempts'}"})
        risk_score += 10

if source_ip != 'unknown' and not private_re.match(source_ip):
    if not any(i['value'] == source_ip for i in iocs):
        iocs.append({"type": "ip", "value": source_ip, "severity": "high", "confidence": "high", "context": "SIEM-identified attack source"})
        risk_score += 10

# 3. Targeted accounts
targeted_users = re.findall(r'(?:for|user|username|login)[=:\s]+([a-zA-Z0-9._-]+)', raw_log, re.IGNORECASE)
user_counts = Counter(targeted_users)
high_value = ['root', 'admin', 'administrator', 'sa', 'postgres', 'mysql', 'oracle', 'www-data', 'daemon']
for user, count in user_counts.most_common(5):
    if user.lower() in high_value:
        findings.append({"title": f"Privileged Account Targeted: {user}", "details": f"High-value account '{user}' targeted {count} time(s) — privilege escalation risk if compromised"})
        risk_score += 15
        iocs.append({"type": "username", "value": user, "severity": "high", "confidence": "high", "context": "Targeted privileged account"})
if username != 'unknown' and username.lower() in high_value:
    if not any(i.get('value') == username for i in iocs if i.get('type') == 'username'):
        findings.append({"title": f"SIEM Target: {username}", "details": f"SIEM identifies privileged account '{username}' as target"})
        risk_score += 10

# 4. Credential stuffing pattern
if len(user_counts) > 5:
    findings.append({"title": "Credential Stuffing Pattern", "details": f"{len(user_counts)} unique usernames targeted from same source — automated credential stuffing attack"})
    risk_score += 15
    verdict = 'true_positive'

# 5. Success after failure
if re.search(r'Accepted|success|authenticated|Logon Type.*10|EventID.*4624', raw_log, re.IGNORECASE) and fail_count > 0:
    findings.append({"title": "Successful Auth After Brute Force", "details": "Account compromise likely — successful authentication detected after multiple failures"})
    risk_score += 20
    verdict = 'true_positive'

# 6. Protocol detection
protocols = []
if re.search(r'ssh|sshd|port\s*22\b', raw_log, re.IGNORECASE): protocols.append('SSH')
if re.search(r'rdp|port\s*3389|Remote Desktop', raw_log, re.IGNORECASE): protocols.append('RDP')
if re.search(r'\bftp\b|port\s*21\b', raw_log, re.IGNORECASE): protocols.append('FTP')
if re.search(r'\bsmb\b|port\s*445\b|port\s*139\b', raw_log, re.IGNORECASE): protocols.append('SMB')
if re.search(r'HTTP|port\s*80\b|port\s*443\b|\b401\b|\b403\b', raw_log, re.IGNORECASE): protocols.append('HTTP')
if protocols:
    findings.append({"title": "Attack Vector Identified", "details": f"Brute force targeting {', '.join(protocols)} protocol(s) on {hostname}"})

# Verdict
risk_score = max(0, min(100, risk_score))
if risk_score >= 80: verdict = 'true_positive'
elif risk_score >= 50 and verdict != 'true_positive': verdict = 'suspicious'
elif risk_score < 40 and fail_count == 0: verdict = 'benign'

if not findings:
    findings.append({"title": "Insufficient Evidence", "details": f"Alert on {hostname} — insufficient log data for automated brute force classification"})
    verdict = 'needs_manual_review'

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    ext_ips = [i['value'] for i in iocs if i['type'] == 'ip']
    if ext_ips: recommendations.append(f"Block attacking IP(s) at perimeter firewall: {', '.join(ext_ips[:5])}")
    recommendations.append(f"Audit authentication logs on {hostname} for the past 24 hours")
    if any(u.lower() in high_value for u in user_counts):
        recommendations.append("Force password reset on targeted privileged accounts and enable MFA")
    recommendations.append("Check for successful logins from attacking IPs — pivot to lateral movement investigation")
else:
    recommendations.append("Continue baseline monitoring — no immediate action required")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 2. PHISHING INVESTIGATION
# ════════════════════════════════════════════════════════════════
TEMPLATES["phishing-investigation"] = r'''import json, re

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
dest_ip = siem_event.get('destination_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Extract URLs
url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]*'
urls = list(set(re.findall(url_pattern, raw_log)))
suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.buzz', '.loan', '.click', '.work', '.date', '.racing']
url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly']

for url in urls:
    sev = 'medium'
    conf = 'high'
    reasons = []
    domain_match = re.search(r'https?://([^/\s:]+)', url)
    domain = domain_match.group(1) if domain_match else ''
    if any(url.lower().endswith(tld) or f'{tld}/' in url.lower() for tld in suspicious_tlds):
        sev = 'high'
        reasons.append('suspicious TLD')
        risk_score += 10
    if any(shortener in url.lower() for shortener in url_shorteners):
        sev = 'high'
        reasons.append('URL shortener (obfuscation)')
        risk_score += 10
    if re.search(r'login|signin|verify|secure|update|confirm|account|password|credential', url, re.IGNORECASE):
        sev = 'critical'
        reasons.append('credential harvesting keywords in URL')
        risk_score += 15
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        sev = 'high'
        reasons.append('raw IP in URL (no domain)')
        risk_score += 10
    ctx = f"Found in alert log{' — ' + ', '.join(reasons) if reasons else ''}"
    iocs.append({"type": "url", "value": url[:200], "severity": sev, "confidence": conf, "context": ctx})
    if domain:
        iocs.append({"type": "domain", "value": domain, "severity": sev, "confidence": conf, "context": ctx})
    if reasons:
        findings.append({"title": f"Suspicious URL: {domain or url[:60]}", "details": f"URL contains {', '.join(reasons)}. Full URL: {url[:120]}"})

# 2. Email header analysis
from_match = re.search(r'From:\s*([^\n]+)', raw_log, re.IGNORECASE)
reply_to = re.search(r'Reply-To:\s*([^\n]+)', raw_log, re.IGNORECASE)
return_path = re.search(r'Return-Path:\s*([^\n]+)', raw_log, re.IGNORECASE)
sender = from_match.group(1).strip() if from_match else ''
if sender:
    email_match = re.search(r'[\w.+-]+@[\w.-]+', sender)
    if email_match:
        iocs.append({"type": "email", "value": email_match.group(), "severity": "medium", "confidence": "high", "context": "Sender email address"})
if from_match and reply_to:
    from_domain = re.search(r'@([\w.-]+)', from_match.group(1))
    reply_domain = re.search(r'@([\w.-]+)', reply_to.group(1))
    if from_domain and reply_domain and from_domain.group(1).lower() != reply_domain.group(1).lower():
        findings.append({"title": "Email Header Mismatch", "details": f"From domain ({from_domain.group(1)}) differs from Reply-To domain ({reply_domain.group(1)}) — common phishing indicator"})
        risk_score += 15

# 3. Urgency / social engineering indicators
urgency_phrases = ['immediate action', 'account suspended', 'verify now', 'urgent', 'expires today',
    'click here immediately', 'your account will be', 'unauthorized access', 'security alert',
    'confirm your identity', 'within 24 hours', 'act now', 'limited time']
found_urgency = [p for p in urgency_phrases if p.lower() in raw_log.lower()]
if found_urgency:
    findings.append({"title": "Social Engineering Indicators", "details": f"Urgency/pressure tactics detected: {', '.join(found_urgency[:5])}"})
    risk_score += 10

# 4. Attachment analysis
attachment_patterns = [r'\.exe\b', r'\.scr\b', r'\.bat\b', r'\.cmd\b', r'\.ps1\b', r'\.vbs\b',
    r'\.js\b', r'\.hta\b', r'\.lnk\b', r'\.pif\b', r'\.msi\b', r'\.jar\b',
    r'\.doc\.exe', r'\.pdf\.exe', r'\.xlsx\.scr']
dangerous_attachments = []
for pat in attachment_patterns:
    matches = re.findall(pat, raw_log, re.IGNORECASE)
    dangerous_attachments.extend(matches)
if dangerous_attachments:
    findings.append({"title": "Dangerous Attachment Detected", "details": f"Potentially malicious file extensions found: {', '.join(set(dangerous_attachments))}"})
    risk_score += 20
    for att in set(dangerous_attachments):
        iocs.append({"type": "filename", "value": att, "severity": "critical", "confidence": "high", "context": "Dangerous executable attachment"})

# 5. Typosquatting check
known_brands = {'microsoft': ['micros0ft', 'microsft', 'micrsoft', 'rnicrosoft'],
    'google': ['g00gle', 'gogle', 'googie'], 'apple': ['app1e', 'appie'],
    'paypal': ['paypa1', 'paypai', 'peypal'], 'amazon': ['amaz0n', 'arnazon']}
for brand, typos in known_brands.items():
    for typo in typos:
        if typo in raw_log.lower():
            findings.append({"title": f"Typosquatting: {typo}", "details": f"Possible impersonation of {brand} — '{typo}' found in content"})
            risk_score += 15
            iocs.append({"type": "domain", "value": typo, "severity": "critical", "confidence": "high", "context": f"Typosquatting {brand}"})

# Verdict
risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35 and not iocs: verdict = 'benign'

if not findings:
    findings.append({"title": "Alert Review", "details": f"Phishing alert for {username}@{hostname} — limited indicators found in available data"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append(f"Quarantine email and block sender domain across email gateway")
    if urls: recommendations.append(f"Block URLs at web proxy: {', '.join(u[:60] for u in urls[:3])}")
    recommendations.append(f"Contact {username} to verify if they clicked any links or opened attachments")
    recommendations.append("Run endpoint scan on user's workstation for malware indicators")
    recommendations.append("Check email gateway logs for similar messages sent to other users")
else:
    recommendations.append("No immediate action — continue monitoring")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 3. RANSOMWARE TRIAGE
# ════════════════════════════════════════════════════════════════
TEMPLATES["ransomware-triage"] = r'''import json, re
from collections import Counter

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

lines = raw_log.strip().split('\n') if raw_log.strip() else []

# 1. Shadow copy / backup destruction
shadow_cmds = ['vssadmin', 'wbadmin', 'bcdedit', 'wmic shadowcopy']
shadow_hits = [cmd for cmd in shadow_cmds if cmd.lower() in raw_log.lower()]
if shadow_hits or re.search(r'delete\s+shadows|recoveryenabled\s+no', raw_log, re.IGNORECASE):
    findings.append({"title": "Backup Destruction Detected", "details": f"Commands associated with backup/shadow copy deletion found ({', '.join(shadow_hits) if shadow_hits else 'recovery disable'}). This is a hallmark ransomware precursor."})
    risk_score += 30

# 2. Mass file encryption
ransom_exts = ['.encrypted', '.locked', '.crypt', '.enc', '.WNCRY', '.cerber', '.locky',
    '.zepto', '.thor', '.aesir', '.zzzzz', '.dharma', '.wallet', '.onion', '.crypted']
rename_count = sum(1 for ext in ransom_exts if ext.lower() in raw_log.lower())
file_rename_count = len(re.findall(r'(?:FileRename|file_rename|rename)', raw_log, re.IGNORECASE))
if rename_count > 0 or file_rename_count >= 3:
    findings.append({"title": "Mass File Encryption", "details": f"Detected {max(rename_count, file_rename_count)} file rename/encryption events with ransomware-associated extensions"})
    risk_score += 25

# 3. Ransom note creation
ransom_notes = ['README_DECRYPT', 'HOW_TO_RECOVER', 'DECRYPT_INSTRUCTIONS', 'RANSOM_NOTE',
    'YOUR_FILES_ARE', 'HELP_DECRYPT', 'RECOVERY_KEY', '!README!', 'RESTORE_FILES']
note_hits = [n for n in ransom_notes if n.lower() in raw_log.lower()]
if note_hits:
    findings.append({"title": "Ransom Note Created", "details": f"Ransom note indicator(s) found: {', '.join(note_hits)}"})
    risk_score += 20

# 4. Suspicious processes
ransom_processes = ['vssadmin.exe', 'cipher.exe', 'wbadmin.exe', 'bcdedit.exe',
    'powershell.exe -enc', 'cmd.exe /c', 'attrib +h', 'icacls']
proc_hits = [p for p in ransom_processes if p.lower() in raw_log.lower()]
if proc_hits:
    findings.append({"title": "Suspicious Process Execution", "details": f"Processes commonly used in ransomware attacks: {', '.join(proc_hits)}"})
    risk_score += 15

# 5. Lateral movement (SMB/network spread)
if re.search(r':445\b|:139\b|SMB|CIFS|net\s+use', raw_log, re.IGNORECASE):
    findings.append({"title": "Network Spread Indicators", "details": "SMB/CIFS activity detected concurrent with encryption — possible worm-like propagation"})
    risk_score += 15
    smb_ips = re.findall(r'(\d+\.\d+\.\d+\.\d+):445', raw_log)
    for ip in set(smb_ips):
        iocs.append({"type": "ip", "value": ip, "severity": "high", "confidence": "high", "context": "SMB lateral movement target"})

# 6. Extract IOCs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
for ip in set(re.findall(ip_pattern, raw_log)):
    if not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', ip):
        if not any(i['value'] == ip for i in iocs):
            iocs.append({"type": "ip", "value": ip, "severity": "high", "confidence": "medium", "context": "External IP in ransomware context"})
hashes = set(re.findall(r'\b[a-fA-F0-9]{64}\b', raw_log)) | set(re.findall(r'\b[a-fA-F0-9]{32}\b', raw_log))
for h in hashes:
    iocs.append({"type": "hash", "value": h, "severity": "critical", "confidence": "high", "context": "File hash in ransomware context"})
    risk_score += 5

if source_ip != 'unknown' and not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', source_ip):
    if not any(i['value'] == source_ip for i in iocs):
        iocs.append({"type": "ip", "value": source_ip, "severity": "critical", "confidence": "high", "context": "SIEM source — possible C2 or initial access"})

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35: verdict = 'benign'

if not findings:
    findings.append({"title": "Ransomware Alert Review", "details": f"Alert on {hostname} — limited ransomware indicators in available data"})

recommendations = []
if verdict == 'true_positive':
    recommendations.append(f"CRITICAL: Immediately isolate {hostname} from the network")
    recommendations.append("Do NOT reboot — preserve RAM for forensic analysis")
    recommendations.append("Identify patient zero and initial access vector")
    recommendations.append("Check backup integrity — verify offline/immutable backups exist")
    recommendations.append("Engage incident response team and legal counsel")
elif verdict == 'suspicious':
    recommendations.append(f"Isolate {hostname} as precaution while investigating")
    recommendations.append("Run full AV/EDR scan on affected system")
    recommendations.append("Check for lateral movement to other hosts")
else:
    recommendations.append("Continue monitoring — no ransomware indicators confirmed")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 4. DATA EXFILTRATION DETECTION
# ════════════════════════════════════════════════════════════════
TEMPLATES["data-exfiltration-detection"] = r'''import json, re

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
dest_ip = siem_event.get('destination_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Transfer volume analysis
size_patterns = [
    (r'(\d+(?:\.\d+)?)\s*GB', 1024),
    (r'(\d+(?:\.\d+)?)\s*MB', 1),
    (r'(\d+(?:\.\d+)?)\s*bytes', 0.000001),
    (r'content.length:\s*(\d+)', 0.000001),
]
total_mb = 0
for pattern, multiplier in size_patterns:
    for match in re.findall(pattern, raw_log, re.IGNORECASE):
        total_mb += float(match) * multiplier
if total_mb > 100:
    findings.append({"title": f"Large Data Transfer: {total_mb:.1f} MB", "details": f"Transfer volume of {total_mb:.1f} MB exceeds normal threshold — possible bulk data exfiltration"})
    risk_score += 25
elif total_mb > 10:
    findings.append({"title": f"Significant Data Transfer: {total_mb:.1f} MB", "details": f"Transfer of {total_mb:.1f} MB detected — warrants review"})
    risk_score += 10

# 2. Cloud storage / exfil destinations
cloud_destinations = {
    's3.amazonaws.com': 'AWS S3', 'blob.core.windows.net': 'Azure Blob',
    'storage.googleapis.com': 'Google Cloud', 'dropbox.com': 'Dropbox',
    'mega.nz': 'MEGA', 'drive.google.com': 'Google Drive',
    'onedrive.live.com': 'OneDrive', 'pastebin.com': 'Pastebin',
    'transfer.sh': 'transfer.sh', 'file.io': 'file.io',
    'wetransfer.com': 'WeTransfer', 'anonfiles.com': 'AnonFiles',
}
for domain, service in cloud_destinations.items():
    if domain.lower() in raw_log.lower():
        findings.append({"title": f"Cloud Storage Destination: {service}", "details": f"Data transfer to {service} ({domain}) detected — potential exfiltration channel"})
        iocs.append({"type": "domain", "value": domain, "severity": "high", "confidence": "high", "context": f"Cloud storage exfil target ({service})"})
        risk_score += 15

# 3. Encoding/compression indicators
encoding_patterns = ['base64', 'gzip', 'deflate', 'encrypted', '.zip', '.7z', '.rar', '.tar.gz', 'Content-Encoding']
encoding_hits = [p for p in encoding_patterns if p.lower() in raw_log.lower()]
if encoding_hits:
    findings.append({"title": "Data Encoding/Compression", "details": f"Encoding indicators found ({', '.join(encoding_hits)}) — data may be obfuscated to evade DLP"})
    risk_score += 10

# 4. Time analysis (off-hours = higher risk)
time_match = re.search(r'(\d{1,2}):(\d{2})(?::(\d{2}))', raw_log)
if time_match:
    hour = int(time_match.group(1))
    if hour < 6 or hour > 22:
        findings.append({"title": "Off-Hours Activity", "details": f"Data transfer at {time_match.group(0)} — outside normal business hours increases exfiltration risk"})
        risk_score += 10

# 5. Sensitive file indicators
sensitive_patterns = [r'\.pst\b', r'\.ost\b', r'\.mdb\b', r'\.sql\b', r'\.csv\b',
    r'password', r'credential', r'secret', r'confidential', r'\.kdbx\b',
    r'customer.*data', r'employee.*record', r'financial', r'SELECT\s.*FROM']
sensitive_hits = [p.replace(r'\b', '') for p in sensitive_patterns if re.search(p, raw_log, re.IGNORECASE)]
if sensitive_hits:
    findings.append({"title": "Sensitive Data Indicators", "details": f"Content suggests sensitive data types: {', '.join(sensitive_hits[:5])}"})
    risk_score += 15

# 6. External destination IPs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
for ip in set(re.findall(ip_pattern, raw_log)):
    if not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', ip):
        if not any(i['value'] == ip for i in iocs):
            iocs.append({"type": "ip", "value": ip, "severity": "high", "confidence": "medium", "context": "External destination in data transfer"})
if dest_ip != 'unknown' and not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', dest_ip):
    if not any(i['value'] == dest_ip for i in iocs):
        iocs.append({"type": "ip", "value": dest_ip, "severity": "high", "confidence": "high", "context": "SIEM-identified exfiltration destination"})
        risk_score += 10

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35: verdict = 'benign'

if not findings:
    findings.append({"title": "Data Transfer Alert", "details": f"Alert from {hostname}/{username} — limited exfiltration indicators"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append(f"Block outbound connections from {hostname} to identified destinations")
    recommendations.append(f"Review DLP logs for {username} over the past 7 days")
    recommendations.append("Check if transferred data is classified or contains PII")
    recommendations.append("Interview user to determine if transfer was authorized")
else:
    recommendations.append("Log and monitor — no confirmed exfiltration")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 5. PRIVILEGE ESCALATION HUNT
# ════════════════════════════════════════════════════════════════
TEMPLATES["privilege-escalation-hunt"] = r'''import json, re

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Sudo/su usage patterns
sudo_hits = re.findall(r'sudo:\s*(\S+)\s*:.*COMMAND=(.*)', raw_log)
su_hits = re.findall(r'su\[\d+\]:\s*.*?(\w+)\s+to\s+(\w+)', raw_log, re.IGNORECASE)
if sudo_hits:
    for user, cmd in sudo_hits:
        findings.append({"title": f"Sudo Execution: {user}", "details": f"User '{user}' executed privileged command: {cmd.strip()[:100]}"})
        if any(dangerous in cmd.lower() for dangerous in ['chmod 777', 'passwd', 'useradd', 'visudo', '/bin/sh', '/bin/bash', 'chown root']):
            risk_score += 20
            findings.append({"title": "Dangerous Sudo Command", "details": f"High-risk privileged command detected: {cmd.strip()[:80]}"})
        else:
            risk_score += 10
if su_hits:
    for from_user, to_user in su_hits:
        findings.append({"title": f"User Switch: {from_user} → {to_user}", "details": f"Account '{from_user}' switched to '{to_user}'"})
        if to_user.lower() in ('root', 'admin'):
            risk_score += 15

# 2. SUID/SGID exploitation
suid_patterns = [r'find.*-perm.*4000', r'find.*-perm.*-u=s', r'chmod\s+[24]755', r'chmod\s+u\+s']
for pat in suid_patterns:
    if re.search(pat, raw_log, re.IGNORECASE):
        findings.append({"title": "SUID/SGID Manipulation", "details": f"Commands associated with SUID exploitation detected"})
        risk_score += 20
        break

# 3. Windows UAC bypass / token manipulation
win_escalation = [
    (r'EventID.*4672|Special privileges assigned', "Privileged Token Assignment"),
    (r'EventID.*4673|Privileged service called', "Privileged Service Call"),
    (r'runas|Start-Process.*-Verb.*RunAs', "RunAs Elevation"),
    (r'fodhelper|eventvwr|sdclt|computerdefaults', "UAC Bypass Technique"),
    (r'SeDebugPrivilege|SeTcbPrivilege|SeImpersonatePrivilege', "Dangerous Privilege Usage"),
    (r'mimikatz|sekurlsa|lsadump|kerberos::golden', "Credential Dumping Tool"),
]
for pattern, title in win_escalation:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": title, "details": f"Windows privilege escalation indicator: {pattern.split('|')[0]}"})
        risk_score += 20

# 4. Kernel/exploit indicators
kernel_patterns = [r'kernel.*exploit', r'dirty.*cow', r'CVE-\d{4}-\d+', r'buffer overflow',
    r'segfault.*in.*libc', r'stack smashing', r'heap corruption']
for pat in kernel_patterns:
    match = re.search(pat, raw_log, re.IGNORECASE)
    if match:
        findings.append({"title": "Exploit Indicator", "details": f"Possible exploitation: '{match.group()}'"})
        risk_score += 25
        iocs.append({"type": "indicator", "value": match.group(), "severity": "critical", "confidence": "medium", "context": "Exploit signature"})

# 5. Service account abuse
if username != 'unknown':
    service_accounts = ['www-data', 'apache', 'nginx', 'daemon', 'nobody', 'mysql', 'postgres', 'jenkins', 'git']
    if username.lower() in service_accounts:
        findings.append({"title": f"Service Account Activity: {username}", "details": f"Service account '{username}' performing unusual actions — service accounts should not execute interactive commands"})
        risk_score += 15
        iocs.append({"type": "username", "value": username, "severity": "high", "confidence": "high", "context": "Service account performing privileged actions"})

# IOCs
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
for ip in set(re.findall(ip_pattern, raw_log)):
    if not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', ip):
        iocs.append({"type": "ip", "value": ip, "severity": "medium", "confidence": "medium", "context": "External IP in privilege escalation context"})

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35: verdict = 'benign'

if not findings:
    findings.append({"title": "Privilege Escalation Alert", "details": f"Alert on {hostname} by {username} — limited escalation indicators"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append(f"Audit all commands executed by {username} on {hostname} in the past 24 hours")
    recommendations.append("Check for persistence mechanisms (cron jobs, systemd units, scheduled tasks)")
    recommendations.append("Review group memberships and sudoers changes")
    recommendations.append("Scan for rootkits and unauthorized SUID binaries")
else:
    recommendations.append("Routine monitoring — no confirmed escalation")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 6. C2 COMMUNICATION HUNT
# ════════════════════════════════════════════════════════════════
TEMPLATES["c2-communication-hunt"] = r'''import json, re, math

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
dest_ip = siem_event.get('destination_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Beacon interval analysis
timestamps = re.findall(r'(\d{2}):(\d{2}):(\d{2})', raw_log)
if len(timestamps) >= 3:
    seconds = [int(h)*3600 + int(m)*60 + int(s) for h, m, s in timestamps]
    intervals = [seconds[i+1] - seconds[i] for i in range(len(seconds)-1) if seconds[i+1] > seconds[i]]
    if intervals:
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals) if len(intervals) > 1 else 0
        stddev = math.sqrt(variance)
        jitter_pct = (stddev / avg_interval * 100) if avg_interval > 0 else 100
        if jitter_pct < 15 and avg_interval > 5:
            findings.append({"title": "Regular Beacon Pattern Detected", "details": f"Callback interval: {avg_interval:.0f}s avg, {jitter_pct:.1f}% jitter ({len(intervals)} samples). Low jitter indicates automated C2 beaconing."})
            risk_score += 25
        elif jitter_pct < 30 and avg_interval > 5:
            findings.append({"title": "Semi-Regular Callback Pattern", "details": f"Interval: {avg_interval:.0f}s avg, {jitter_pct:.1f}% jitter — possible C2 with jitter configured"})
            risk_score += 15

# 2. DGA domain detection (entropy analysis)
domains = re.findall(r'(?:query|dns|domain|host)[=:\s]+([a-z0-9][-a-z0-9]{3,62}\.[a-z]{2,})', raw_log, re.IGNORECASE)
domains += re.findall(r'https?://([a-z0-9][-a-z0-9]{3,62}\.[a-z]{2,})', raw_log, re.IGNORECASE)
for domain in set(domains):
    label = domain.split('.')[0]
    if len(label) > 4:
        freq = {}
        for c in label.lower():
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((count/len(label)) * math.log2(count/len(label)) for count in freq.values())
        if entropy > 3.5 and len(label) > 8:
            findings.append({"title": f"Possible DGA Domain: {domain}", "details": f"High entropy ({entropy:.2f} bits) in domain label suggests algorithmically generated domain"})
            iocs.append({"type": "domain", "value": domain, "severity": "critical", "confidence": "medium", "context": f"Possible DGA domain (entropy: {entropy:.2f})"})
            risk_score += 15

# 3. Known C2 framework signatures
c2_indicators = [
    (r'cobalt\s*strike|beacon\.dll|beacon\.exe', "Cobalt Strike"),
    (r'meterpreter|metasploit|reverse_tcp|reverse_https', "Metasploit/Meterpreter"),
    (r'empire|invoke-empire|stager', "Empire"),
    (r'covenant|grunt|elite', "Covenant"),
    (r'sliver|implant|mtls', "Sliver"),
    (r'\.ps1.*-enc|-encodedcommand|powershell.*base64', "Encoded PowerShell (C2 stager)"),
]
for pattern, framework in c2_indicators:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"C2 Framework Signature: {framework}", "details": f"Pattern matching known {framework} indicators found in log data"})
        risk_score += 25
        iocs.append({"type": "indicator", "value": framework, "severity": "critical", "confidence": "high", "context": f"C2 framework signature"})

# 4. Non-standard ports with HTTP/HTTPS
port_pattern = r':(\d{4,5})\b'
ports = [int(p) for p in re.findall(port_pattern, raw_log)]
standard_ports = {80, 443, 8080, 8443, 8000, 3000}
unusual_ports = [p for p in set(ports) if p not in standard_ports and 1024 < p < 65535]
if unusual_ports and re.search(r'HTTP|HTTPS|GET|POST|PUT', raw_log, re.IGNORECASE):
    findings.append({"title": f"HTTP on Non-Standard Port(s): {', '.join(str(p) for p in unusual_ports[:5])}", "details": "HTTP traffic on unusual ports may indicate C2 communication attempting to bypass firewall rules"})
    risk_score += 10

# 5. External destination
if dest_ip != 'unknown' and not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', dest_ip):
    iocs.append({"type": "ip", "value": dest_ip, "severity": "high", "confidence": "high", "context": "SIEM-identified C2 destination"})
    risk_score += 10

for ip in set(re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b', raw_log)):
    if not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', ip):
        if not any(i['value'] == ip for i in iocs):
            iocs.append({"type": "ip", "value": ip, "severity": "high", "confidence": "medium", "context": "External IP in C2 context"})

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35 and not iocs: verdict = 'benign'

if not findings:
    findings.append({"title": "C2 Alert Review", "details": f"C2 communication alert from {hostname} — limited indicators found"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    c2_ips = [i['value'] for i in iocs if i['type'] == 'ip']
    c2_domains = [i['value'] for i in iocs if i['type'] == 'domain']
    if c2_ips: recommendations.append(f"Block C2 IPs at firewall: {', '.join(c2_ips[:5])}")
    if c2_domains: recommendations.append(f"Sinkhole C2 domains: {', '.join(c2_domains[:5])}")
    recommendations.append(f"Isolate {hostname} and run full malware scan")
    recommendations.append("Capture network traffic for PCAP analysis")
    recommendations.append("Check for persistence mechanisms on affected host")
else:
    recommendations.append("Continue network monitoring — no confirmed C2")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 7. INSIDER THREAT DETECTION
# ════════════════════════════════════════════════════════════════
TEMPLATES["insider-threat-detection"] = r'''import json, re

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Off-hours access
time_match = re.search(r'(\d{1,2}):(\d{2})(?::(\d{2}))', raw_log)
if time_match:
    hour = int(time_match.group(1))
    if hour < 6 or hour >= 22:
        findings.append({"title": "Off-Hours Access", "details": f"Activity at {time_match.group(0)} — outside normal business hours (06:00-22:00) increases insider threat risk"})
        risk_score += 15
weekend_patterns = [r'Saturday', r'Sunday', r'Sat\b', r'Sun\b']
if any(re.search(p, raw_log, re.IGNORECASE) for p in weekend_patterns):
    findings.append({"title": "Weekend Activity", "details": "Activity detected on weekend — review if consistent with user's normal pattern"})
    risk_score += 10

# 2. Bulk data access
bulk_patterns = [
    (r'SELECT\s+\*\s+FROM', "Unrestricted database query (SELECT *)"),
    (r'COPY\s+.*TO\s', "Database COPY export"),
    (r'mysqldump|pg_dump|mongodump', "Database dump utility"),
    (r'(\d+)\s+(?:rows|records|items)\s+(?:exported|downloaded|returned)', "Bulk record access"),
    (r'download.*(?:all|entire|complete|full)', "Full dataset download"),
    (r'export.*(?:csv|xlsx|json|xml)', "Data export to file"),
]
for pattern, description in bulk_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": "Bulk Data Access", "details": description})
        risk_score += 15

# 3. Privilege abuse / outside-role access
access_patterns = [
    (r'(?:HR|payroll|salary|compensation)\s+(?:database|table|record|file)', "HR/payroll data access"),
    (r'(?:customer|client)\s+(?:database|table|record|PII)', "Customer data access"),
    (r'(?:financial|banking|invoice)\s+(?:record|statement|data)', "Financial data access"),
    (r'admin.*panel|management.*console', "Admin panel access"),
]
for pattern, description in access_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": "Sensitive Data Access", "details": f"{description} by {username} — verify authorization"})
        risk_score += 10

# 4. Data staging / exfiltration prep
staging_patterns = [
    (r'\.zip\b|\.7z\b|\.rar\b|\.tar\b', "Archive creation (data staging)"),
    (r'USB|removable|thumb.*drive|external.*drive', "Removable media usage"),
    (r'personal.*email|gmail|yahoo|hotmail|protonmail', "Personal email service"),
    (r'dropbox|drive\.google|onedrive|mega\.nz', "Personal cloud storage"),
    (r'airdrop|bluetooth.*transfer|nearby.*share', "Local file transfer"),
]
for pattern, description in staging_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": "Data Staging Indicator", "details": description})
        risk_score += 10

# 5. Volume anomaly
size_match = re.search(r'(\d+(?:\.\d+)?)\s*(?:GB|MB|files|documents|records)', raw_log, re.IGNORECASE)
if size_match:
    findings.append({"title": "Data Volume Indicator", "details": f"Activity involves {size_match.group()} — compare to user baseline"})
    risk_score += 10

# 6. HR context (resignation/termination)
hr_patterns = [r'resign', r'terminat', r'notice period', r'last day', r'exit interview', r'offboard']
hr_hits = [p for p in hr_patterns if re.search(p, raw_log, re.IGNORECASE)]
if hr_hits:
    findings.append({"title": "HR Risk Context", "details": f"Indicators suggest employee separation context: {', '.join(hr_hits)} — elevated insider threat risk"})
    risk_score += 20

# IOCs
if username != 'unknown':
    iocs.append({"type": "username", "value": username, "severity": "high", "confidence": "high", "context": "Subject of insider threat investigation"})
if source_ip != 'unknown':
    iocs.append({"type": "ip", "value": source_ip, "severity": "medium", "confidence": "high", "context": "Source IP for insider activity"})

domains = re.findall(r'https?://([a-zA-Z0-9.-]+)', raw_log)
for d in set(domains):
    if any(personal in d.lower() for personal in ['gmail', 'yahoo', 'hotmail', 'protonmail', 'dropbox', 'mega.nz']):
        iocs.append({"type": "domain", "value": d, "severity": "high", "confidence": "high", "context": "Personal service used for data transfer"})

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35: verdict = 'benign'

if not findings:
    findings.append({"title": "Insider Threat Alert", "details": f"Alert for {username} on {hostname} — limited behavioral indicators"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append(f"Review all access logs for {username} over the past 30 days")
    recommendations.append("Cross-reference with HR records for any separation/performance issues")
    recommendations.append("Enable enhanced monitoring (DLP, UEBA) on this user account")
    recommendations.append("Coordinate with management before direct user engagement")
else:
    recommendations.append("Baseline monitoring — no confirmed insider threat indicators")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 8. LATERAL MOVEMENT DETECTION
# ════════════════════════════════════════════════════════════════
TEMPLATES["lateral-movement-detection"] = r'''import json, re
from collections import Counter

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
dest_ip = siem_event.get('destination_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Remote execution tools
remote_tools = [
    (r'PsExec|psexec\.exe|PSEXESVC', "PsExec Remote Execution"),
    (r'wmic\s+.*\/node|Win32_Process.*Create', "WMI Remote Execution"),
    (r'winrm|Invoke-Command.*-ComputerName|Enter-PSSession', "WinRM/PowerShell Remoting"),
    (r'smbexec|atexec|dcomexec', "Impacket Remote Execution"),
    (r'sc\s+\\\\.*create|sc\.exe.*\\\\', "Remote Service Creation"),
    (r'schtasks.*\/create.*\/s\s', "Remote Scheduled Task"),
    (r'reg\s+.*\\\\.*add', "Remote Registry Modification"),
]
for pattern, tool_name in remote_tools:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"Remote Execution: {tool_name}", "details": f"Lateral movement via {tool_name} detected — attacker moving between hosts"})
        risk_score += 20

# 2. RDP lateral movement
if re.search(r'RDP|Remote Desktop|port\s*3389|LogonType.*10|TermService', raw_log, re.IGNORECASE):
    findings.append({"title": "RDP Lateral Movement", "details": "Remote Desktop connection detected — common lateral movement technique"})
    risk_score += 15

# 3. Pass-the-hash / pass-the-ticket
pth_patterns = [
    (r'NTLM.*(?:pass|relay)|overpass.the.hash', "Pass-the-Hash"),
    (r'kerberos.*ticket|golden.*ticket|silver.*ticket|\.kirbi', "Pass-the-Ticket"),
    (r'LogonType.*9|NewCredentials', "New Credentials Logon (PTH indicator)"),
    (r'sekurlsa|lsadump|kerberos::ptt', "Credential Dumping (Mimikatz)"),
]
for pattern, technique in pth_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"Credential Abuse: {technique}", "details": f"{technique} indicators found — attacker reusing stolen credentials"})
        risk_score += 25
        iocs.append({"type": "indicator", "value": technique, "severity": "critical", "confidence": "high", "context": "Credential abuse technique"})

# 4. Multi-hop detection
ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
all_ips = list(set(re.findall(ip_pattern, raw_log)))
internal_ips = [ip for ip in all_ips if re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)', ip)]
if len(internal_ips) >= 3:
    findings.append({"title": f"Multi-Host Activity: {len(internal_ips)} Internal IPs", "details": f"Activity spanning {len(internal_ips)} internal hosts suggests multi-hop lateral movement: {', '.join(internal_ips[:5])}"})
    risk_score += 15
    for ip in internal_ips:
        iocs.append({"type": "ip", "value": ip, "severity": "high", "confidence": "medium", "context": "Internal host in lateral movement chain"})

# 5. SMB/Admin share access
if re.search(r'\$|C\$|ADMIN\$|IPC\$|\\\\.*\\[a-zA-Z]\$', raw_log, re.IGNORECASE):
    findings.append({"title": "Admin Share Access", "details": "Administrative share (C$, ADMIN$, IPC$) access detected — often used for lateral movement"})
    risk_score += 15

# 6. External IPs (possible C2 directing lateral movement)
for ip in all_ips:
    if not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', ip):
        iocs.append({"type": "ip", "value": ip, "severity": "high", "confidence": "medium", "context": "External IP in lateral movement context (possible C2)"})

if source_ip != 'unknown': iocs.append({"type": "ip", "value": source_ip, "severity": "high", "confidence": "high", "context": "Source of lateral movement"})
if dest_ip != 'unknown': iocs.append({"type": "ip", "value": dest_ip, "severity": "high", "confidence": "high", "context": "Lateral movement destination"})
if username != 'unknown': iocs.append({"type": "username", "value": username, "severity": "high", "confidence": "high", "context": "Account used for lateral movement"})

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35: verdict = 'benign'

if not findings:
    findings.append({"title": "Lateral Movement Alert", "details": f"Alert from {hostname} — limited lateral movement indicators"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append(f"Isolate affected hosts: {', '.join(internal_ips[:5]) if internal_ips else hostname}")
    recommendations.append("Disable compromised account and force credential reset across affected systems")
    recommendations.append("Audit all systems for unauthorized services, scheduled tasks, and startup items")
    recommendations.append("Check for data exfiltration from accessed hosts")
else:
    recommendations.append("Monitor network for additional lateral movement indicators")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 9. NETWORK BEACONING
# ════════════════════════════════════════════════════════════════
TEMPLATES["network-beaconing"] = r'''import json, re, math

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
dest_ip = siem_event.get('destination_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Beacon interval analysis
timestamps = re.findall(r'(\d{2}):(\d{2}):(\d{2})', raw_log)
if len(timestamps) >= 3:
    seconds = [int(h)*3600 + int(m)*60 + int(s) for h, m, s in timestamps]
    intervals = [seconds[i+1] - seconds[i] for i in range(len(seconds)-1) if seconds[i+1] > seconds[i]]
    if intervals:
        avg = sum(intervals) / len(intervals)
        variance = sum((x - avg)**2 for x in intervals) / len(intervals) if len(intervals) > 1 else 0
        stddev = math.sqrt(variance)
        jitter = (stddev / avg * 100) if avg > 0 else 100
        if jitter < 10 and avg > 5:
            findings.append({"title": "Confirmed Beacon Pattern", "details": f"Highly regular callbacks: {avg:.0f}s interval, {jitter:.1f}% jitter across {len(intervals)} samples. Classic C2 beacon behavior."})
            risk_score += 30
        elif jitter < 25 and avg > 5:
            findings.append({"title": "Probable Beacon Pattern", "details": f"Semi-regular callbacks: {avg:.0f}s interval, {jitter:.1f}% jitter. Consistent with C2 beacon with jitter configuration."})
            risk_score += 20

# 2. DNS anomalies
dns_queries = re.findall(r'(?:query|DNS|lookup)[=:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', raw_log, re.IGNORECASE)
if dns_queries:
    unique_domains = set(dns_queries)
    if len(dns_queries) > len(unique_domains) * 2:
        findings.append({"title": "Repetitive DNS Queries", "details": f"{len(dns_queries)} queries for {len(unique_domains)} unique domains — repetition consistent with beaconing"})
        risk_score += 10
    # Check for random subdomain pattern (DNS tunneling)
    subdomain_lengths = []
    for d in unique_domains:
        parts = d.split('.')
        if len(parts) >= 3:
            subdomain_lengths.append(len(parts[0]))
    if subdomain_lengths and sum(subdomain_lengths)/len(subdomain_lengths) > 15:
        findings.append({"title": "DNS Tunneling Indicator", "details": f"Long random subdomains detected (avg {sum(subdomain_lengths)/len(subdomain_lengths):.0f} chars) — possible DNS tunneling for C2 or data exfiltration"})
        risk_score += 20

    for domain in unique_domains:
        label = domain.split('.')[0]
        if len(label) > 4:
            freq = {}
            for c in label.lower():
                freq[c] = freq.get(c, 0) + 1
            entropy = -sum((cnt/len(label)) * math.log2(cnt/len(label)) for cnt in freq.values())
            if entropy > 3.5 and len(label) > 8:
                iocs.append({"type": "domain", "value": domain, "severity": "high", "confidence": "medium", "context": f"High-entropy domain (DGA indicator, entropy: {entropy:.2f})"})
                risk_score += 10

# 3. Fixed payload size
sizes = re.findall(r'(?:size|length|bytes)[=:\s]+(\d+)', raw_log, re.IGNORECASE)
if len(sizes) >= 3:
    int_sizes = [int(s) for s in sizes]
    avg_size = sum(int_sizes) / len(int_sizes)
    size_var = sum((s - avg_size)**2 for s in int_sizes) / len(int_sizes) if len(int_sizes) > 1 else 0
    if math.sqrt(size_var) < avg_size * 0.1 and avg_size > 0:
        findings.append({"title": "Fixed Payload Size", "details": f"Consistent packet sizes (~{avg_size:.0f} bytes) across {len(int_sizes)} transmissions — characteristic of C2 heartbeat"})
        risk_score += 15

# 4. Destination analysis
if dest_ip != 'unknown' and not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', dest_ip):
    iocs.append({"type": "ip", "value": dest_ip, "severity": "high", "confidence": "high", "context": "Beacon destination IP"})
    risk_score += 10

domains_in_log = re.findall(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]{3,62}\.[a-zA-Z]{2,})', raw_log)
suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.buzz']
for domain in set(domains_in_log):
    if any(domain.lower().endswith(tld) for tld in suspicious_tlds):
        iocs.append({"type": "domain", "value": domain, "severity": "high", "confidence": "high", "context": "Suspicious TLD beacon destination"})
        findings.append({"title": f"Suspicious Beacon Destination: {domain}", "details": f"Beaconing to domain with suspicious TLD"})
        risk_score += 10

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35 and not iocs: verdict = 'benign'

if not findings:
    findings.append({"title": "Network Beaconing Alert", "details": f"Alert from {hostname} — limited beaconing indicators"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append(f"Block destination IPs/domains at perimeter firewall")
    recommendations.append(f"Run full malware scan on {hostname}")
    recommendations.append("Capture 24-hour PCAP for frequency analysis")
    recommendations.append("Check for persistence mechanisms on affected host")
else:
    recommendations.append("Continue monitoring network traffic patterns")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 10. CLOUD INFRASTRUCTURE ATTACK
# ════════════════════════════════════════════════════════════════
TEMPLATES["cloud-infrastructure-attack"] = r'''import json, re

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. IAM / permission changes
iam_patterns = [
    (r'CreateRole|CreateUser|AttachRolePolicy|PutRolePolicy|AddUserToGroup', "IAM Role/User Creation"),
    (r'AssumeRole|GetSessionToken|GetFederationToken', "Role Assumption"),
    (r'CreateAccessKey|UpdateAccessKey', "Access Key Modification"),
    (r'iam\.amazonaws|azuread|cloud\.google\.com/iam', "IAM Service Access"),
    (r'AdministratorAccess|PowerUserAccess|\*:\*', "Overprivileged Policy"),
    (r'SetIamPolicy|setIamPolicy|roles/owner', "GCP IAM Modification"),
]
for pattern, description in iam_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"IAM Change: {description}", "details": f"Cloud identity/access modification detected — {description.lower()} by {username}"})
        risk_score += 20

# 2. Unusual API calls
unusual_apis = [
    (r'CreateTrail|StopLogging|DeleteTrail|UpdateTrail', "CloudTrail Tampering"),
    (r'DeleteFlowLogs|DeleteLogGroup|PutRetentionPolicy.*days.*1\b', "Log Deletion/Manipulation"),
    (r'RunInstances|CreateFunction|CreateBucket', "Resource Creation"),
    (r'AuthorizeSecurityGroupIngress|CreateSecurityGroup.*0\.0\.0\.0', "Security Group Modification"),
    (r'DisableKey|ScheduleKeyDeletion|DisableKeyRotation', "KMS Key Manipulation"),
    (r'PutBucketPolicy.*Principal.*\*', "Public Bucket Policy"),
]
for pattern, description in unusual_apis:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"Suspicious API: {description}", "details": f"{description} — may indicate attacker establishing persistence or covering tracks"})
        risk_score += 15

# 3. Cross-region activity
regions = re.findall(r'(?:us|eu|ap|sa|ca|me|af)-(?:east|west|north|south|central|northeast|southeast)-\d', raw_log)
unique_regions = set(regions)
if len(unique_regions) >= 3:
    findings.append({"title": f"Multi-Region Activity: {len(unique_regions)} Regions", "details": f"Activity across regions: {', '.join(unique_regions)} — unusual unless organization operates globally"})
    risk_score += 15

# 4. Resource creation spikes
create_events = len(re.findall(r'Create|Launch|Run|Allocate|Provision', raw_log, re.IGNORECASE))
if create_events >= 5:
    findings.append({"title": f"Resource Creation Spike: {create_events} Events", "details": f"{create_events} resource creation events — possible cryptomining deployment or infrastructure hijacking"})
    risk_score += 15

# 5. Access from unusual location
if source_ip != 'unknown':
    if not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', source_ip):
        iocs.append({"type": "ip", "value": source_ip, "severity": "high", "confidence": "high", "context": "Cloud API access from external IP"})
        risk_score += 10

# 6. Credential exposure
cred_patterns = [
    (r'AKIA[A-Z0-9]{16}', "AWS Access Key ID"),
    (r'(?:aws_secret|secret_access_key)[=:\s]+[\w/+]{40}', "AWS Secret Key"),
    (r'(?:password|secret|token)[=:\s]+[^\s]{8,}', "Credential in plaintext"),
]
for pattern, description in cred_patterns:
    match = re.search(pattern, raw_log)
    if match:
        findings.append({"title": f"Credential Exposure: {description}", "details": f"{description} found in log data — rotate immediately"})
        risk_score += 20
        # Redact before storing as IOC
        iocs.append({"type": "credential", "value": f"{description} (redacted)", "severity": "critical", "confidence": "high", "context": "Exposed credential"})

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35: verdict = 'benign'

if not findings:
    findings.append({"title": "Cloud Security Alert", "details": f"Alert for {username} — limited cloud attack indicators"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append("Rotate all access keys and credentials for affected accounts")
    recommendations.append("Review CloudTrail/audit logs for the past 72 hours")
    recommendations.append("Revert unauthorized IAM/permission changes")
    recommendations.append("Enable MFA on all cloud admin accounts")
    recommendations.append("Check for unauthorized resources (EC2, Lambda, S3) and terminate")
else:
    recommendations.append("Continue monitoring cloud audit logs")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''

# ════════════════════════════════════════════════════════════════
# 11. SUPPLY CHAIN COMPROMISE
# ════════════════════════════════════════════════════════════════
TEMPLATES["supply-chain-compromise"] = r'''import json, re

siem_event = json.loads("""{{siem_event_json}}""")
raw_log = siem_event.get('raw_log', '')
source_ip = siem_event.get('source_ip', 'unknown')
hostname = siem_event.get('hostname', 'unknown')
username = siem_event.get('username', 'unknown')

findings = []
iocs = []
risk_score = 30
verdict = 'suspicious'

# 1. Hash/checksum mismatches
hash_mismatch = re.findall(r'(?:hash|checksum|digest|sha256|sha1|md5)\s*(?:mismatch|failed|invalid|unexpected|changed|different)', raw_log, re.IGNORECASE)
if hash_mismatch:
    findings.append({"title": "Hash/Checksum Mismatch", "details": f"Integrity verification failure detected ({len(hash_mismatch)} instances) — package may have been tampered with"})
    risk_score += 25
    for h in set(re.findall(r'\b[a-fA-F0-9]{64}\b', raw_log)):
        iocs.append({"type": "hash", "value": h, "severity": "critical", "confidence": "high", "context": "Hash in integrity failure"})
    for h in set(re.findall(r'\b[a-fA-F0-9]{40}\b', raw_log)):
        iocs.append({"type": "hash", "value": h, "severity": "critical", "confidence": "high", "context": "SHA1 hash in integrity failure"})

# 2. Unauthorized package versions
version_patterns = [
    (r'(?:unexpected|unauthorized|unknown)\s+(?:version|package|dependency)', "Unknown package version"),
    (r'(?:downgrade|rollback)\s+(?:detected|warning)', "Package downgrade"),
    (r'(?:yanked|deprecated|removed)\s+(?:version|package)', "Removed package referenced"),
    (r'version\s+\d+\.\d+\.\d+.*(?:not found|missing|unavailable)', "Version mismatch"),
]
for pattern, description in version_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"Package Anomaly: {description}", "details": description})
        risk_score += 15

# 3. Typosquatted package names
typosquat_indicators = [
    (r'(?:lodash|loadash|lodashs|1odash)', "lodash typosquat"),
    (r'(?:crossenv|cross-env)', "cross-env typosquat"),
    (r'(?:event-stream|eventstream|event_stream)', "event-stream"),
    (r'(?:colors\.js|colour\.js|colorss)', "colors typosquat"),
    (r'(?:ua-parser-js|ua_parser|uaparser)', "ua-parser-js"),
]
for pattern, pkg_name in typosquat_indicators:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"Known Supply Chain Package: {pkg_name}", "details": f"Package name matches known supply chain attack pattern"})
        risk_score += 20

# 4. Build pipeline modifications
pipeline_patterns = [
    (r'(?:Jenkinsfile|\.gitlab-ci|\.github/workflows|Dockerfile|docker-compose).*(?:modified|changed|updated)', "CI/CD config modified"),
    (r'(?:npm|pip|gem|cargo)\s+(?:publish|push)', "Package published"),
    (r'(?:pre-install|post-install|preinstall|postinstall)\s+(?:script|hook)', "Install hook execution"),
    (r'(?:curl|wget|Invoke-WebRequest).*(?:sh|bash|powershell)', "Remote script execution in build"),
    (r'(?:eval|exec)\s*\(.*(?:http|ftp|base64)', "Dynamic code execution from network"),
]
for pattern, description in pipeline_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"Build Pipeline Risk: {description}", "details": description})
        risk_score += 15

# 5. Unsigned/unverified packages
unsigned_patterns = [
    (r'(?:unsigned|unverified|no signature|signature.*invalid)', "Unsigned package"),
    (r'(?:GPG|PGP).*(?:error|failed|missing|invalid)', "Signature verification failure"),
    (r'(?:certificate|cert).*(?:expired|invalid|self-signed|untrusted)', "Certificate issue"),
]
for pattern, description in unsigned_patterns:
    if re.search(pattern, raw_log, re.IGNORECASE):
        findings.append({"title": f"Verification Issue: {description}", "details": f"{description} — package authenticity cannot be confirmed"})
        risk_score += 15

# 6. Extract package names and URLs as IOCs
pkg_names = re.findall(r'(?:package|module|dependency|library)[=:\s]+["\']?([a-zA-Z0-9._-]+)', raw_log, re.IGNORECASE)
for pkg in set(pkg_names):
    iocs.append({"type": "package", "value": pkg, "severity": "medium", "confidence": "medium", "context": "Package referenced in supply chain alert"})

urls = re.findall(r'https?://[^\s<>"]+', raw_log)
for url in set(urls):
    iocs.append({"type": "url", "value": url[:200], "severity": "medium", "confidence": "high", "context": "URL in supply chain context"})

if source_ip != 'unknown' and not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', source_ip):
    iocs.append({"type": "ip", "value": source_ip, "severity": "medium", "confidence": "medium", "context": "External IP in supply chain context"})

risk_score = max(0, min(100, risk_score))
if risk_score >= 75: verdict = 'true_positive'
elif risk_score >= 50: verdict = 'suspicious'
elif risk_score < 35: verdict = 'benign'

if not findings:
    findings.append({"title": "Supply Chain Alert", "details": f"Alert on {hostname} — limited supply chain compromise indicators"})

recommendations = []
if verdict in ('true_positive', 'suspicious'):
    recommendations.append("Freeze all deployments until investigation completes")
    recommendations.append("Verify all package hashes against known-good versions")
    recommendations.append("Audit recent changes to CI/CD pipeline configurations")
    recommendations.append("Review dependency lock files for unauthorized changes")
    recommendations.append("Scan all build artifacts for malicious code")
else:
    recommendations.append("Routine supply chain monitoring — no confirmed compromise")

print(json.dumps({"findings": findings, "iocs": iocs, "risk_score": risk_score, "verdict": verdict, "recommendations": recommendations}))
'''


def main():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            for slug, template in TEMPLATES.items():
                cur.execute(
                    "UPDATE agent_skills SET code_template = %s WHERE skill_slug = %s",
                    (template, slug),
                )
                if cur.rowcount == 0:
                    print(f"  WARNING: No skill found with slug '{slug}'")
                else:
                    print(f"  Updated: {slug}")
        conn.commit()
        print(f"\nAll {len(TEMPLATES)} templates updated successfully.")
    except Exception as e:
        conn.rollback()
        print(f"ERROR: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
