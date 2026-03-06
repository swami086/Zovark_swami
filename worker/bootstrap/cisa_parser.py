"""Parse CISA Known Exploited Vulnerabilities JSON."""

import json


def parse_cisa_kev(filepath: str) -> list:
    """Parse known_exploited_vulnerabilities.json.

    Returns list of dicts with: cve_id, vendor, product, name, description,
    date_added, due_date
    """
    with open(filepath, "r") as f:
        data = json.load(f)

    vulns = []
    for v in data.get("vulnerabilities", []):
        vulns.append({
            "cve_id": v.get("cveID", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "description": v.get("shortDescription", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
        })

    return vulns
