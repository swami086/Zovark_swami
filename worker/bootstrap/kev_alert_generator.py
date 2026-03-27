"""Generate synthetic SIEM alerts from CISA KEV entries.

Converts KEV vulnerability records into siem_alerts-format dicts
suitable for ingestion and investigation by the ZOVARC pipeline.
"""
import uuid
from datetime import datetime


def generate_kev_alert(kev_entry: dict) -> dict:
    """Convert a KEV entry into a siem_alerts-format dict.

    Args:
        kev_entry: {cve_id, vendor, product, name, description, date_added?, due_date?}

    Returns:
        siem_alerts-format dict with source='cisa-kev-bootstrap', severity='critical'
    """
    cve_id = kev_entry.get('cve_id', 'UNKNOWN')
    vendor = kev_entry.get('vendor', '')
    product = kev_entry.get('product', '')
    name = kev_entry.get('name', '')
    description = kev_entry.get('description', '')
    date_added = kev_entry.get('date_added', '')
    due_date = kev_entry.get('due_date', '')

    title = f"CISA KEV: {cve_id} — {vendor} {product}"
    if name:
        title = f"CISA KEV: {cve_id} — {name}"

    alert_body = (
        f"Known Exploited Vulnerability detected.\n\n"
        f"CVE: {cve_id}\n"
        f"Vendor: {vendor}\n"
        f"Product: {product}\n"
        f"Vulnerability: {name}\n"
        f"Description: {description}\n"
    )
    if date_added:
        alert_body += f"Date Added to KEV: {date_added}\n"
    if due_date:
        alert_body += f"Remediation Due Date: {due_date}\n"

    return {
        'id': str(uuid.uuid4()),
        'title': title,
        'alert_name': f'KEV-{cve_id}',
        'severity': 'critical',
        'source': 'cisa-kev-bootstrap',
        'source_alert_id': cve_id,
        'raw_data': alert_body,
        'status': 'new',
        'created_at': datetime.utcnow().isoformat(),
        # Entity hints for extraction
        'vendor': vendor,
        'product': product,
        'cve_id': cve_id,
    }
