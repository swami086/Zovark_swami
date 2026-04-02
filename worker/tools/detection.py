"""Detection tools — composite tools that combine extraction, parsing, and scoring."""
import re
import json
import math
from collections import Counter

from tools.extraction import extract_ipv4, extract_usernames, extract_urls, extract_domains, extract_emails, _make_ioc
from tools.parsing import parse_windows_event, parse_auth_log, parse_dns_query
from tools.scoring import score_brute_force, score_phishing, score_c2_beacon, score_exfiltration, score_generic
from tools.analysis import calculate_entropy, count_pattern

import ipaddress


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP is RFC1918 private (10.x, 172.16-31.x, 192.168.x) or loopback.
    RFC5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) are treated
    as external/public since they represent real external IPs in SIEM test data."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return True
        # RFC1918 only — not RFC5737 documentation ranges
        rfc1918 = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(addr in net for net in rfc1918)
    except ValueError:
        return False


def detect_kerberoasting(siem_event: dict) -> dict:
    """Detect Kerberoasting: RC4 encryption (0x17), TGS requests for SPNs."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    parsed = parse_windows_event(raw_log)
    event_id = parsed.get("EventID", "")
    encryption = parsed.get("TicketEncryptionType", "")
    service_name = parsed.get("ServiceName", "")

    # RC4 encryption (0x17) — primary indicator
    if encryption == "0x17":
        findings.append("RC4 encryption (0x17) detected — weak encryption type commonly used in Kerberoasting")
        risk += 40

    # TGS request (4769) for service accounts
    if event_id == "4769":
        findings.append(f"TGS ticket request (EventID 4769) for service: {service_name}")
        risk += 15
        if service_name and "krbtgt" not in service_name.lower():
            findings.append(f"Non-krbtgt service SPN targeted: {service_name}")
            risk += 15

    # Extract IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    usernames = extract_usernames(raw_log)
    iocs.extend(usernames)

    # Service account as IOC
    if service_name:
        iocs.append(_make_ioc("service_name", service_name, raw_log))

    # Source IP from siem_event
    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # Username from siem_event
    username = siem_event.get("username", "")
    if username and not any(i["value"] == username for i in iocs):
        iocs.append(_make_ioc("username", username, raw_log))

    # Kerberoasting requires BOTH RC4 encryption AND TGS request for non-krbtgt service
    is_rc4 = encryption == "0x17"
    is_tgs = event_id == "4769"
    is_krbtgt = service_name and "krbtgt" in service_name.lower()
    
    # Only high risk if RC4 + TGS for actual service (not krbtgt)
    if is_rc4 and is_tgs and not is_krbtgt:
        risk = max(risk, 55)
    elif is_rc4 and is_tgs and is_krbtgt:
        # RC4 TGT request - suspicious but not kerberoasting
        risk = 25
    elif is_rc4:
        # RC4 used but not TGS - moderate concern
        risk = max(risk, 30)
    elif is_tgs and not is_krbtgt:
        # TGS without RC4 - low concern
        risk = max(risk, 15)
    
    if not findings:
        risk = max(risk, 10)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_golden_ticket(siem_event: dict) -> dict:
    """Detect Golden Ticket: forged TGT, RC4 encryption, abnormal lifetime."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    parsed = parse_windows_event(raw_log)
    event_id = parsed.get("EventID", "")
    encryption = parsed.get("TicketEncryptionType", "")
    service_name = parsed.get("ServiceName", "")
    ticket_options = parsed.get("TicketOptions", "")
    lifetime = parsed.get("Lifetime", "")

    # TGT request with RC4
    if event_id == "4768" and encryption == "0x17":
        findings.append("TGT request with RC4 encryption — possible Golden Ticket")
        risk += 40

    # krbtgt service targeted
    if service_name and "krbtgt" in service_name.lower():
        findings.append(f"krbtgt service targeted: {service_name}")
        risk += 20

    # Abnormal lifetime (check both parsed and raw log)
    if lifetime:
        hour_match = re.search(r'(\d+)h', lifetime)
        if hour_match and int(hour_match.group(1)) > 720:  # > 30 days
            findings.append(f"Abnormally long ticket lifetime: {lifetime}")
            risk += 35
    # Also check raw log for lifetime patterns
    raw_lifetime = re.search(r'Lifetime[=:\s](\d+)h', raw_log)
    if raw_lifetime:
        hours = int(raw_lifetime.group(1))
        if hours > 100:  # > ~4 days is suspicious
            findings.append(f"Extended ticket lifetime: {hours}h")
            risk += 35

    # Suspicious ticket options
    if ticket_options and ticket_options.startswith("0x50"):
        findings.append(f"Suspicious ticket options: {ticket_options}")
        risk += 15
    
    # Also check raw log for ticket options
    if re.search(r'TicketOptions[=:\s]0x50', raw_log):
        findings.append("Suspicious ticket options in raw log")
        risk += 15

    # IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    username = siem_event.get("username", "")
    if username:
        iocs.append(_make_ioc("username", username, raw_log))

    if not findings:
        risk = max(risk, 10)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_ransomware(siem_event: dict) -> dict:
    """Detect ransomware: shadow copy deletion, mass encryption, ransom notes."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Shadow copy deletion
    if re.search(r'vssadmin\s+delete\s+shadows', raw_lower):
        findings.append("Shadow copy deletion detected (vssadmin delete shadows)")
        risk += 40
    if re.search(r'wmic\s+shadowcopy\s+delete', raw_lower):
        findings.append("Shadow copy deletion via WMI")
        risk += 40

    # Mass encryption indicators
    if re.search(r'mass\s+encrypt', raw_lower):
        findings.append("Mass encryption activity detected")
        risk += 30

    # File extension changes
    ransom_extensions = [r'\.locked', r'\.encrypted', r'\.crypt', r'\.ransom', r'\.cry\b']
    for ext in ransom_extensions:
        if re.search(ext, raw_lower):
            findings.append(f"Ransomware file extension detected: {ext.replace(chr(92), '')}")
            risk += 25
            break

    # Ransom notes
    if re.search(r'ransom|readme\.txt|decrypt|bitcoin|btc|payment', raw_lower):
        findings.append("Ransom-related language detected")
        risk += 20

    # IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i.get("value") == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # Ransomware indicators should have minimum risk if detected
    if findings and risk < 50:
        risk = 60  # Ensure detection meets threshold
    
    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_phishing(siem_event: dict) -> dict:
    """Detect phishing: suspicious URLs, credential harvesting, urgency language."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Extract URLs and domains
    urls = extract_urls(raw_log)
    domains = extract_domains(raw_log)
    emails = extract_emails(raw_log)

    iocs.extend(urls)
    iocs.extend(domains)
    iocs.extend(emails)

    # Urgency language
    urgency_patterns = [r'urgent', r'immediate', r'verify.*account', r'suspend', r'expire',
                        r'click\s+here', r'act\s+now', r'wire\s+transfer', r'confirm.*identity']
    has_urgency = False
    for pat in urgency_patterns:
        if re.search(pat, raw_lower):
            has_urgency = True
            findings.append(f"Urgency/social engineering language detected: {pat}")
            risk += 10
            break

    # Credential form indicators
    has_cred_form = bool(re.search(r'login|password|credential|verify|secure.*login', raw_lower))
    if has_cred_form:
        findings.append("Credential harvesting indicators detected")
        risk += 20

    # Suspicious domains
    suspicious_count = 0
    for d in domains:
        domain_val = d["value"]
        if re.search(r'(login|secure|verify|account|update|confirm)', domain_val):
            suspicious_count += 1
            findings.append(f"Suspicious domain: {domain_val}")
            risk += 15

    # URL count
    if len(urls) > 0:
        risk += 10

    # Compound: URL + urgency together is high-confidence phishing
    if len(urls) > 0 and has_urgency:
        risk += 10

    # Spoofed sender
    if re.search(r'from:?\s*\S+@\S+', raw_lower) and domains:
        findings.append("Email with embedded URLs detected")
        risk += 5

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_c2(siem_event: dict) -> dict:
    """Detect C2: regular beacon intervals, DGA domains, encoded payloads."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Extract IOCs
    ips = extract_ipv4(raw_log)
    domains = extract_domains(raw_log)
    iocs.extend(ips)
    iocs.extend(domains)

    # Beacon interval detection
    interval_match = re.search(r'(?:beacon|interval)\s*[=:]?\s*(\d+)\s*s', raw_lower)
    stddev_match = re.search(r'stddev\s*=\s*([\d.]+)', raw_lower)
    conn_match = re.search(r'connections?\s*=\s*(\d+)', raw_lower)

    avg_interval = float(interval_match.group(1)) if interval_match else 0
    stddev = float(stddev_match.group(1)) if stddev_match else 999
    connections = int(conn_match.group(1)) if conn_match else 0

    if avg_interval > 0 and stddev < 5:
        findings.append(f"Regular beacon interval detected: {avg_interval}s (stddev={stddev})")
        risk += 30

    if connections >= 100:
        findings.append(f"High connection count: {connections}")
        risk += 20

    # DGA domain detection — entropy OR explicit "DGA" keyword + random-looking subdomain
    dga_detected = False
    for d in domains:
        subdomain = d["value"].split(".")[0]
        entropy = calculate_entropy(subdomain)
        # Short random subdomains (< 10 chars) have lower entropy but are still suspicious
        entropy_threshold = 3.0 if len(subdomain) <= 8 else 3.5
        if entropy > entropy_threshold:
            findings.append(f"High-entropy domain (possible DGA): {d['value']} (entropy={entropy:.2f})")
            risk += 25
            dga_detected = True
            break
    # Also detect DGA via keyword
    if not dga_detected and re.search(r'\bdga\b', raw_lower):
        findings.append("DGA (Domain Generation Algorithm) keyword detected")
        risk += 20
        dga_detected = True

    # C2 keywords
    c2_keywords = ["beacon", "c2", "command.and.control", "callback", "implant", "cobalt", "meterpreter"]
    for kw in c2_keywords:
        if kw in raw_lower:
            findings.append(f"C2 keyword detected: {kw}")
            risk += 10
            break

    # Port 443 to unusual destination (check raw_log for :443 even if IP was filtered)
    if re.search(r':443\b', raw_log):
        risk += 5

    # Compound bonus: multiple C2 indicators together is high confidence
    c2_indicator_count = sum([
        avg_interval > 0 and stddev < 5,
        connections >= 100,
        dga_detected,
    ])
    if c2_indicator_count >= 3:
        risk += 15
    elif c2_indicator_count >= 2:
        risk += 10

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_data_exfil(siem_event: dict) -> dict:
    """Detect data exfiltration: large transfers, off-hours, external dest."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Extract IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    # Data volume
    size_match = re.search(r'([\d.]+)\s*(GB|MB|KB|TB|bytes?)\b', raw_log, re.IGNORECASE)
    bytes_transferred = 0
    if size_match:
        amount = float(size_match.group(1))
        unit = size_match.group(2).upper()
        multipliers = {"TB": 1e12, "GB": 1e9, "MB": 1e6, "KB": 1e3, "BYTE": 1, "BYTES": 1}
        bytes_transferred = int(amount * multipliers.get(unit, 1))
        if bytes_transferred > 100 * 1024 * 1024:  # > 100MB
            findings.append(f"Large data transfer: {size_match.group(0)}")
            risk += 30

    # External destination — keyword, non-RFC1918 IP, or "transferred to <IP>" pattern
    is_external = bool(re.search(r'external|internet|public|outside', raw_lower))
    if not is_external and ips:
        # Check if any extracted IP is a public (non-RFC1918) address
        for ip_ioc in ips:
            ip_val = ip_ioc.get("value", "")
            if ip_val and not _is_private_ip(ip_val):
                is_external = True
                break
    if not is_external:
        # Check for "to <IP>" patterns in raw_log — IPs may have been filtered by extract_ipv4
        dest_ip_match = re.search(r'(?:to|destination|dest)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log, re.IGNORECASE)
        if dest_ip_match:
            dest_ip = dest_ip_match.group(1)
            if not _is_private_ip(dest_ip):
                is_external = True
                iocs.append(_make_ioc("ipv4", dest_ip, raw_log))
    if is_external:
        findings.append("Transfer to external destination")
        risk += 20

    # Off-hours
    is_off_hours = bool(re.search(r'off.hours|after.hours|night|weekend|0[0-5]:\d{2}', raw_lower))
    if is_off_hours:
        findings.append("Activity during off-hours")
        risk += 15

    # Encryption/encoding
    is_encrypted = bool(re.search(r'encrypt|encoded|base64|compressed|archive', raw_lower))
    if is_encrypted:
        findings.append("Data appears encrypted or encoded")
        risk += 10

    # Cloud storage
    if re.search(r'dropbox|gdrive|onedrive|s3|azure.blob|mega\.nz', raw_lower):
        findings.append("Cloud storage destination detected")
        risk += 10

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_lolbin_abuse(siem_event: dict) -> dict:
    """Detect LOLBin abuse: certutil, mshta, bitsadmin, rundll32, etc."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # LOLBin patterns with malicious indicators
    lolbin_patterns = {
        "certutil": [
            (r'certutil.*-urlcache', "certutil download via -urlcache"),
            (r'certutil.*-split.*-f', "certutil download with -split -f"),
            (r'certutil.*-decode', "certutil base64 decode"),
            (r'certutil.*-encode', "certutil base64 encode"),
        ],
        "mshta": [
            (r'mshta\s+(?:http|vbscript|javascript)', "mshta executing remote/scripted content"),
        ],
        "bitsadmin": [
            (r'bitsadmin.*transfer', "bitsadmin file transfer"),
            (r'bitsadmin.*/download', "bitsadmin download"),
        ],
        "rundll32": [
            (r'rundll32.*javascript', "rundll32 executing JavaScript"),
            (r'rundll32.*shell32', "rundll32 shell32 abuse"),
        ],
        "regsvr32": [
            (r'regsvr32.*/s.*/u.*scrobj', "regsvr32 scriptlet execution (Squiblydoo)"),
            (r'regsvr32.*http', "regsvr32 remote COM object"),
        ],
        "wscript": [
            (r'wscript.*\.js\b', "wscript executing JavaScript"),
            (r'cscript.*\.vbs\b', "cscript executing VBScript"),
        ],
    }

    for lolbin, patterns in lolbin_patterns.items():
        for pattern, description in patterns:
            if re.search(pattern, raw_lower):
                findings.append(f"LOLBin abuse: {description}")
                risk += 35
                break

    # Compound certutil: -urlcache + -split + -f together is high-confidence download
    if re.search(r'certutil', raw_lower) and re.search(r'-urlcache', raw_lower) and re.search(r'-split', raw_lower) and re.search(r'-f\b', raw_lower):
        findings.append("Certutil compound download flags (-urlcache -split -f) — high confidence")
        risk += 20

    # Extract any URLs (download targets)
    urls = extract_urls(raw_log)
    iocs.extend(urls)

    # URL pointing to suspicious file extensions
    for url_ioc in urls:
        url_val = url_ioc.get("value", "")
        if re.search(r'\.(exe|dll|bin|bat|ps1|vbs|hta|scr)\b', url_val, re.IGNORECASE):
            findings.append(f"URL targets suspicious executable: {url_val}")
            risk += 10
            break

    # Extract IPs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    # Check for suspicious file paths
    if re.search(r'\\temp\\|\\tmp\\|\\appdata\\|\\public\\', raw_lower):
        findings.append("Suspicious output path (temp/appdata/public)")
        risk += 10

    # Executable extensions
    if re.search(r'\.(exe|dll|bat|ps1|vbs|js|hta)\b', raw_lower):
        risk += 5

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i.get("value") == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # Benign certutil usage (just -verify)
    if re.search(r'certutil.*-verify', raw_lower) and not findings:
        risk = min(risk, 15)

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}



def detect_com_hijacking(siem_event: dict) -> dict:
    """Detect COM hijacking via registry modifications."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # COM hijacking registry paths
    com_patterns = [
        r'HKCU\\Software\\Classes\\CLSID',
        r'HKEY_CURRENT_USER\\Software\\Classes\\CLSID',
        r'HKLM\\Software\\Classes\\CLSID',
        r'InprocServer32',
        r'LocalServer32',
    ]
    
    for pattern in com_patterns:
        if re.search(pattern, raw_log, re.IGNORECASE):
            findings.append(f"COM hijacking registry path detected: {pattern}")
            risk += 25
    
    # Suspicious DLL in user-writable location
    if re.search(r'InprocServer32.*\\Users\\.*\.dll', raw_log, re.IGNORECASE):
        findings.append("COM DLL registered in user-writable location")
        risk += 30
    
    # DLL that differs from system default
    if re.search(r'shell32\.dll|kernel32\.dll|kernelbase\.dll', raw_lower):
        if re.search(r'\\Users\\|\\Temp\\|\\AppData\\', raw_lower):
            findings.append("System DLL replaced with user-controlled path")
            risk += 35
    
    if findings:
        risk = max(risk, 75)  # Minimum risk for COM hijacking
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_encoded_service(siem_event: dict) -> dict:
    """Detect malicious services with encoded commands."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # New service installation
    if re.search(r'EventID\s*=\s*(7045|4697)', raw_log):
        findings.append("New Windows service installed")
        risk += 20
    
    # Encoded PowerShell in service
    encoded_patterns = [
        r'-enc\s+[A-Za-z0-9+/]{20,}',  # -enc with base64
        r'-encodedcommand\s+[A-Za-z0-9+/]{20,}',
        r'-e\s+[A-Za-z0-9+/]{20,}',
    ]
    
    for pattern in encoded_patterns:
        if re.search(pattern, raw_lower):
            findings.append("Encoded command in service ImagePath")
            risk += 40
            break
    
    # PowerShell in service path
    if re.search(r'powershell\.exe|pwsh\.exe', raw_lower):
        findings.append("PowerShell executable in service")
        risk += 15
        
        # Suspicious PowerShell flags
        if re.search(r'-nop|-noprofile', raw_lower):
            findings.append("PowerShell -NoProfile flag (evasion)")
            risk += 10
        if re.search(r'-w\s+hidden|-windowstyle\s+hidden', raw_lower):
            findings.append("PowerShell hidden window")
            risk += 15
        if re.search(r'downloadstring|iex\s|invoke-expression', raw_lower):
            findings.append("PowerShell download/cradle detected")
            risk += 25
    
    # Only flag as malicious if there's actual encoded/obfuscated content
    malicious_indicators = ['Encoded command', 'download/cradle', 'hidden window']
    has_malicious = any(mi in ' '.join(findings) for mi in malicious_indicators)
    
    if has_malicious:
        risk = max(risk, 80)
    elif findings and risk < 10:
        risk = 5  # Benign service creation
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_token_impersonation(siem_event: dict) -> dict:
    """Detect token impersonation via RunAs."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # RunAs usage
    if re.search(r'runas\.exe', raw_lower):
        findings.append("RunAs.exe execution detected")
        risk += 15
    
    # Saved credentials flag
    if re.search(r'/savecred', raw_lower):
        findings.append("RunAs with saved credentials (/savecred)")
        risk += 25
    
    # Elevated user target
    if re.search(r'admin|system|domain', raw_lower):
        findings.append("Privilege escalation target detected")
        risk += 20
    
    # Encoded command after runas
    if re.search(r'-enc\s+|/enc\s+|-encodedcommand', raw_lower):
        findings.append("Encoded command in RunAs context")
        risk += 35
    
    # Suspicious execution after impersonation
    if re.search(r'powershell|cmd\.exe|wscript|cscript', raw_lower):
        findings.append("Script execution following impersonation")
        risk += 20
    
    # Only flag if /savecred is used (the actual credential theft vector)
    has_savecred = '/savecred' in raw_lower
    has_encoded = '-enc' in raw_lower or '-encodedcommand' in raw_lower
    
    if has_savecred or has_encoded:
        risk = max(risk, 85)
    elif findings and risk < 20:
        risk = 10  # Benign runas usage
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_appcert_dlls(siem_event: dict) -> dict:
    """Detect AppCert DLLs persistence."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # AppCertDlls registry path
    if re.search(r'AppCertDlls', raw_log, re.IGNORECASE):
        findings.append("AppCertDlls registry modification detected")
        risk += 40
    
    # Session Manager path
    if re.search(r'Session Manager.*AppCert', raw_log, re.IGNORECASE):
        findings.append("Session Manager AppCert configuration")
        risk += 35
    
    # DLL in suspicious location
    if re.search(r'AppCertDlls.*\\Windows\\[^\\]+\.dll', raw_log, re.IGNORECASE):
        findings.append("Custom DLL in AppCertDlls")
        risk += 30
    
    # Registry modification by non-system user
    if re.search(r'\\Users\\|\\Temp\\', raw_lower):
        findings.append("AppCert DLL from user-writable location")
        risk += 25
    
    # Only flag if there's actual DLL registration in AppCert path
    has_dll_registration = 'custom dll' in ' '.join(findings).lower()
    has_user_location = 'user-writable' in ' '.join(findings).lower()
    
    if has_dll_registration or has_user_location:
        risk = max(risk, 85)
    elif findings and risk < 20:
        risk = 10  # Benign mention
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}
