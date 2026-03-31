"""Extraction tools — IOC and entity extraction from text with evidence_refs."""
import re
from urllib.parse import urlparse


def _make_ioc(ioc_type, value, source_text, source_field="text"):
    start = source_text.find(str(value))
    snippet = source_text[max(0, start - 20):start + len(str(value)) + 20] if start >= 0 else str(value)
    return {"type": ioc_type, "value": str(value), "evidence_refs": [{"source": source_field, "raw_text": snippet[:60]}]}


# --- False positive exclusion lists ---
EXCLUDE_IPV4 = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
# RFC5737 documentation ranges
_RFC5737_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
EXCLUDE_DOMAINS = {"localhost", "example.com", "test.local", "example.org", "example.net"}


def extract_ipv4(text: str) -> list:
    """Extract IPv4 addresses from text, excluding loopback/broadcast/RFC5737."""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    results = []
    seen = set()
    for match in re.finditer(pattern, text):
        ip = match.group()
        # Validate octets
        parts = ip.split(".")
        if not all(0 <= int(p) <= 255 for p in parts):
            continue
        if ip in EXCLUDE_IPV4:
            continue
        if ip.startswith(_RFC5737_PREFIXES):
            continue
        if ip not in seen:
            seen.add(ip)
            results.append(_make_ioc("ipv4", ip, text))
    return results


def extract_ipv6(text: str) -> list:
    """Extract IPv6 addresses from text, excluding ::1 loopback."""
    # Match full and compressed IPv6
    pattern = r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:)*::[0-9a-fA-F:]*\b'
    results = []
    seen = set()
    for match in re.finditer(pattern, text):
        ip = match.group()
        if ip == "::1":
            continue
        if ip not in seen:
            seen.add(ip)
            results.append(_make_ioc("ipv6", ip, text))
    return results


def extract_domains(text: str) -> list:
    """Extract domain names with TLD validation."""
    # Common TLDs for validation
    valid_tlds = {
        "com", "org", "net", "io", "gov", "edu", "mil", "info", "biz", "co",
        "us", "uk", "de", "fr", "jp", "cn", "ru", "br", "au", "in", "ca",
        "es", "it", "nl", "se", "no", "fi", "dk", "pl", "cz", "at", "ch",
        "be", "pt", "ie", "nz", "za", "mx", "ar", "cl", "xyz", "top",
        "club", "online", "site", "tech", "dev", "app", "cloud",
    }
    pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    results = []
    seen = set()
    for match in re.finditer(pattern, text):
        domain = match.group().lower()
        if domain in EXCLUDE_DOMAINS:
            continue
        # Check TLD
        tld = domain.rsplit(".", 1)[-1]
        if tld not in valid_tlds:
            continue
        # Skip IP-like patterns
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            continue
        if domain not in seen:
            seen.add(domain)
            results.append(_make_ioc("domain", domain, text))
    return results


def extract_urls(text: str) -> list:
    """Extract full URLs (http/https/ftp) from text."""
    pattern = r'(?:https?|ftp)://[^\s<>\"\')\]}>]+'
    results = []
    seen = set()
    for match in re.finditer(pattern, text):
        url = match.group().rstrip(".,;:")
        if url not in seen:
            seen.add(url)
            results.append(_make_ioc("url", url, text))
    return results


def extract_hashes(text: str) -> list:
    """Extract MD5 (32), SHA1 (40), SHA256 (64) hex hashes."""
    pattern = r'\b[0-9a-fA-F]{32,64}\b'
    results = []
    seen = set()
    for match in re.finditer(pattern, text):
        h = match.group().lower()
        if len(h) == 32:
            hash_type = "md5"
        elif len(h) == 40:
            hash_type = "sha1"
        elif len(h) == 64:
            hash_type = "sha256"
        else:
            continue
        if h not in seen:
            seen.add(h)
            results.append(_make_ioc(hash_type, h, text))
    return results


def extract_emails(text: str) -> list:
    """Extract email addresses from text."""
    pattern = r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    results = []
    seen = set()
    for match in re.finditer(pattern, text):
        email = match.group().lower()
        if email not in seen:
            seen.add(email)
            results.append(_make_ioc("email", email, text))
    return results


def extract_usernames(text: str) -> list:
    """Extract usernames from SIEM patterns: User=, TargetUserName=, SubjectUserName=, Account Name:."""
    patterns = [
        r'(?:User|TargetUserName|SubjectUserName|AccountName|Account Name)\s*[:=]\s*(\S+)',
        r'(?:user|username)\s*[:=]\s*(\S+)',
    ]
    results = []
    seen = set()
    for pat in patterns:
        for match in re.finditer(pat, text, re.IGNORECASE):
            username = match.group(1).strip(",;\"'")
            if username and username not in seen:
                seen.add(username)
                results.append(_make_ioc("username", username, text))
    return results


def extract_cves(text: str) -> list:
    """Extract CVE identifiers (CVE-YYYY-NNNNN format)."""
    pattern = r'\bCVE-\d{4}-\d{4,}\b'
    results = []
    seen = set()
    for match in re.finditer(pattern, text, re.IGNORECASE):
        cve = match.group().upper()
        if cve not in seen:
            seen.add(cve)
            results.append(_make_ioc("cve", cve, text))
    return results
