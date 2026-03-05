"""Entity normalization and hashing for cross-tenant deduplication.

Pure stdlib Python — no external dependencies.
"""

import hashlib
import ipaddress
import re
from urllib.parse import urlparse, urlunparse

# Tracking params to strip from URLs
_TRACKING_PARAMS = frozenset({
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'msclkid', 'mc_eid', 'ref', 'source',
})


def normalize_ip(value: str) -> str:
    """Normalize IP address. Handles IPv4, IPv6, defanged [.], port stripping."""
    v = value.strip()
    # Defang: replace [.] with .
    v = v.replace('[.]', '.').replace('[:]', ':')
    # Strip brackets (IPv6 in URLs)
    v = v.strip('[]')
    # Strip port suffix for IPv4 (1.2.3.4:8080)
    if ':' in v and '.' in v and v.count(':') == 1:
        v = v.rsplit(':', 1)[0]
    try:
        addr = ipaddress.ip_address(v)
        if isinstance(addr, ipaddress.IPv6Address):
            return addr.exploded
        return str(addr)
    except ValueError:
        return v.lower()


def normalize_domain(value: str) -> str:
    """Normalize domain. Lowercase, strip www., trailing dot, handle defang."""
    v = value.strip().lower()
    # Defang
    v = v.replace('[.]', '.').replace('hxxp://', '').replace('hxxps://', '')
    v = v.replace('http://', '').replace('https://', '')
    # Strip path/query if present
    v = v.split('/')[0]
    # Strip trailing dot (FQDN notation)
    v = v.rstrip('.')
    # Strip www.
    if v.startswith('www.'):
        v = v[4:]
    return v


def normalize_file_hash(value: str) -> str:
    """Normalize file hash. Lowercase, validate hex + length (MD5/SHA1/SHA256)."""
    v = value.strip().lower()
    # Strip common prefixes
    for prefix in ('md5:', 'sha1:', 'sha256:', 'sha-256:', 'sha-1:'):
        if v.startswith(prefix):
            v = v[len(prefix):]
            break
    v = v.strip()
    if re.match(r'^[a-f0-9]+$', v) and len(v) in (32, 40, 64):
        return v
    return v


def normalize_url(value: str) -> str:
    """Normalize URL. Lowercase scheme+host, remove tracking params, defang."""
    v = value.strip()
    # Defang
    v = v.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
    v = v.replace('[.]', '.').replace('[:]', ':')
    try:
        parsed = urlparse(v)
        scheme = (parsed.scheme or 'http').lower()
        host = (parsed.netloc or '').lower()
        path = parsed.path.rstrip('/')
        # Filter tracking params from query
        if parsed.query:
            params = parsed.query.split('&')
            filtered = [p for p in params if p.split('=')[0].lower() not in _TRACKING_PARAMS]
            query = '&'.join(filtered)
        else:
            query = ''
        return urlunparse((scheme, host, path, '', query, ''))
    except Exception:
        return v.lower()


def normalize_email(value: str) -> str:
    """Normalize email. Lowercase, strip plus-addressing."""
    v = value.strip().lower()
    if '@' in v:
        local, domain = v.rsplit('@', 1)
        # Strip plus-addressing
        if '+' in local:
            local = local.split('+')[0]
        return f"{local}@{domain}"
    return v


_NORMALIZERS = {
    'ip': normalize_ip,
    'domain': normalize_domain,
    'file_hash': normalize_file_hash,
    'url': normalize_url,
    'email': normalize_email,
}


def normalize_entity(entity_type: str, value: str) -> str:
    """Dispatch to type-specific normalizer. Falls back to strip+lower."""
    normalizer = _NORMALIZERS.get(entity_type)
    if normalizer:
        return normalizer(value)
    return value.strip().lower()


def compute_entity_hash(entity_type: str, normalized_value: str) -> str:
    """SHA256 hash of '{type}:{normalized_value}' for cross-tenant dedup."""
    key = f"{entity_type}:{normalized_value}"
    return hashlib.sha256(key.encode('utf-8')).hexdigest()
