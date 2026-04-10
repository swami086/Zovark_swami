"""
Privacy-preserving structural anonymization for customer-side collection (Ticket 5).

Uses HMAC-SHA256 with a tenant-specific key so pseudonyms are stable per deployment
without reversible storage of raw PII. Writes Parquet for efficient batch upload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from typing import Any, Dict, List, Optional, Set

# Field names (case-insensitive) treated as PII for structural anonymization
DEFAULT_PII_FIELDS: Set[str] = {
    "email",
    "user_email",
    "username",
    "user",
    "user_name",
    "src_user",
    "dst_user",
    "source_ip",
    "dest_ip",
    "src_ip",
    "dst_ip",
    "ip",
    "ipv4",
    "ipv6",
    "host",
    "hostname",
    "machine",
    "phone",
    "mobile",
    "account",
    "employee_id",
    "serial",
}

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+", re.I)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def _collection_secret() -> bytes:
    raw = os.environ.get("ZOVARK_COLLECTION_ANONYMIZATION_KEY", "").strip()
    if not raw:
        raw = os.environ.get("ZOVARK_PLATFORM_API_KEY", "").strip()
    if not raw:
        raise ValueError(
            "Set ZOVARK_COLLECTION_ANONYMIZATION_KEY or ZOVARK_PLATFORM_API_KEY for keyed anonymization"
        )
    return hashlib.sha256(raw.encode("utf-8")).digest()


def anonymize_token(value: str, secret: bytes) -> str:
    """Stable keyed pseudonym (hex prefix of HMAC-SHA256)."""
    if not value or not isinstance(value, str):
        return ""
    mac = hmac.new(secret, value.strip().encode("utf-8"), hashlib.sha256).hexdigest()
    return f"pseudo_{mac[:24]}"


def _scrub_string(s: str, secret: bytes) -> str:
    out = _EMAIL_RE.sub(lambda m: anonymize_token(m.group(0), secret), s)
    out = _IPV4_RE.sub(lambda m: anonymize_token(m.group(0), secret), out)
    return out


def anonymize_structure(obj: Any, secret: bytes, pii_fields: Optional[Set[str]] = None) -> Any:
    """Recursively replace PII field values and inline emails/IPs in strings."""
    fields = {f.lower() for f in (pii_fields or DEFAULT_PII_FIELDS)}
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            kl = k.lower() if isinstance(k, str) else k
            if isinstance(k, str) and kl in fields and isinstance(v, str):
                out[k] = anonymize_token(v, secret)
            else:
                out[k] = anonymize_structure(v, secret, pii_fields)
        return out
    if isinstance(obj, list):
        return [anonymize_structure(x, secret, pii_fields) for x in obj]
    if isinstance(obj, str):
        return _scrub_string(obj, secret)
    return obj


def rows_to_parquet(rows: List[Dict[str, Any]], out_path: str) -> str:
    """Write list of dict rows to Parquet (requires pyarrow)."""
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as e:
        raise ImportError("anonymizer Parquet output requires pyarrow; pip install pyarrow") from e

    if not rows:
        raise ValueError("no rows to write")
    keys = sorted({k for r in rows for k in r.keys()})
    cols = {k: [json.dumps(r.get(k), default=str) if not isinstance(r.get(k), (str, int, float, bool, type(None))) else r.get(k) for r in rows] for k in keys}
    table = pa.table(cols)
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    pq.write_table(table, out_path)
    return out_path


def anonymize_records_for_export(
    records: List[Dict[str, Any]],
    *,
    pii_fields: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    secret = _collection_secret()
    return [anonymize_structure(dict(r), secret, pii_fields) for r in records]
