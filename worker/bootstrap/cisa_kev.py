"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion.

Air-gap support: checks for bundled file at
/app/bootstrap_data/known_exploited_vulnerabilities.json before downloading.

Usage as Temporal activity or standalone:
    python -m bootstrap.cisa_kev --download   # download only
    python -m bootstrap.cisa_kev --parse      # parse bundled file
    python -m bootstrap.cisa_kev --store      # parse + store to DB
"""

import os
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# Air-gap bundle paths (checked in order)
BUNDLE_PATHS = [
    "/app/bootstrap_data/known_exploited_vulnerabilities.json",
    "/app/bootstrap_data/cisa/known_exploited_vulnerabilities.json",
    os.path.join(os.path.dirname(__file__), "data", "known_exploited_vulnerabilities.json"),
]


def find_bundled_kev() -> Optional[str]:
    """Find a bundled CISA KEV file. Returns path or None."""
    for path in BUNDLE_PATHS:
        if os.path.isfile(path):
            logger.info("Found bundled CISA KEV at %s", path)
            return path
    return None


def download_kev(dest_path: Optional[str] = None) -> str:
    """Download CISA KEV catalog.

    Args:
        dest_path: Where to save. Defaults to a temp file.

    Returns:
        Path to downloaded file.

    Raises:
        RuntimeError: If download fails.
    """
    import httpx

    if dest_path is None:
        dest_path = os.path.join(tempfile.gettempdir(), "known_exploited_vulnerabilities.json")

    logger.info("Downloading CISA KEV from %s", CISA_KEV_URL)
    try:
        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            resp = client.get(CISA_KEV_URL)
            resp.raise_for_status()
            Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
            with open(dest_path, "wb") as f:
                f.write(resp.content)
        logger.info("Downloaded CISA KEV to %s (%d bytes)", dest_path, os.path.getsize(dest_path))
        return dest_path
    except Exception as e:
        raise RuntimeError(f"Failed to download CISA KEV: {e}") from e


def resolve_kev_path() -> str:
    """Resolve KEV path: bundled file first, then download.

    Returns:
        Path to KEV JSON file.

    Raises:
        RuntimeError: If neither bundled nor download succeeds.
    """
    bundled = find_bundled_kev()
    if bundled:
        return bundled

    logger.info("No bundled KEV file found, attempting download")
    return download_kev()


def parse_kev_catalog(filepath: str) -> list:
    """Parse CISA KEV JSON catalog.

    Returns list of dicts with: cve_id, vendor, product, vulnerability_name,
    description, date_added, due_date, required_action, known_ransomware_use, notes
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    catalog_version = data.get("catalogVersion", "unknown")
    count = data.get("count", 0)
    logger.info("CISA KEV catalog version=%s, count=%d", catalog_version, count)

    vulns = []
    for v in data.get("vulnerabilities", []):
        vulns.append({
            "cve_id": v.get("cveID", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "description": v.get("shortDescription", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "required_action": v.get("requiredAction", ""),
            "known_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            "notes": v.get("notes", ""),
        })

    logger.info("Parsed %d CISA KEV entries", len(vulns))
    return vulns


def store_kev_catalog(vulns: list, db_url: str = "") -> int:
    """Batch upsert vulnerabilities into kev_catalog table.

    Returns number of entries upserted.
    """
    import psycopg2
    from psycopg2.extras import execute_values

    if not db_url:
        db_url = os.environ.get(
            "DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
        )

    valid = [v for v in vulns if v.get("cve_id")]
    if not valid:
        return 0

    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            values = [
                (
                    v["cve_id"],
                    v["vendor"],
                    v["product"],
                    v.get("vulnerability_name", ""),
                    v.get("description", ""),
                    v.get("date_added") or None,
                    v.get("due_date") or None,
                    v.get("required_action", ""),
                    v.get("known_ransomware_use", False),
                    v.get("notes", ""),
                )
                for v in valid
            ]
            execute_values(
                cur,
                """INSERT INTO kev_catalog
                   (cve_id, vendor, product, vulnerability_name, description,
                    date_added, due_date, required_action, known_ransomware_use, notes,
                    last_synced)
                   VALUES %s
                   ON CONFLICT (cve_id) DO UPDATE SET
                       vendor = EXCLUDED.vendor,
                       product = EXCLUDED.product,
                       vulnerability_name = EXCLUDED.vulnerability_name,
                       description = EXCLUDED.description,
                       date_added = EXCLUDED.date_added,
                       due_date = EXCLUDED.due_date,
                       required_action = EXCLUDED.required_action,
                       known_ransomware_use = EXCLUDED.known_ransomware_use,
                       notes = EXCLUDED.notes,
                       last_synced = NOW()""",
                values,
                template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            )
        conn.commit()
        logger.info("Upserted %d KEV entries", len(valid))
        return len(valid)
    finally:
        conn.close()


def store_to_bootstrap_corpus(vulns: list, db_url: str = "") -> int:
    """Also store KEV entries into bootstrap_corpus for investigation generation.

    Returns number of entries inserted (skips existing).
    """
    import psycopg2
    from psycopg2.extras import execute_values

    if not db_url:
        db_url = os.environ.get(
            "DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
        )

    valid = [v for v in vulns if v.get("cve_id")]
    if not valid:
        return 0

    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            values = [
                (
                    "cisa",
                    v["cve_id"],
                    f"{v['vendor']} {v['product']}: {v.get('vulnerability_name', '')}",
                    v.get("description", ""),
                )
                for v in valid
            ]
            execute_values(
                cur,
                """INSERT INTO bootstrap_corpus (source, source_id, title, description)
                   VALUES %s
                   ON CONFLICT DO NOTHING""",
                values,
                template="(%s, %s, %s, %s)",
            )
            inserted = cur.rowcount
        conn.commit()
        logger.info("Inserted %d KEV entries into bootstrap_corpus", inserted)
        return inserted
    finally:
        conn.close()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if "--download" in sys.argv:
        dest = download_kev()
        print(f"Downloaded to: {dest}")
    elif "--parse" in sys.argv:
        path = resolve_kev_path()
        vulns = parse_kev_catalog(path)
        print(f"KEV entries: {len(vulns)}")
        if vulns:
            print(f"Sample: {vulns[0]['cve_id']} - {vulns[0]['vendor']} {vulns[0]['product']}")
    elif "--store" in sys.argv:
        path = resolve_kev_path()
        vulns = parse_kev_catalog(path)
        stored = store_kev_catalog(vulns)
        corpus = store_to_bootstrap_corpus(vulns)
        print(f"Stored {stored} to kev_catalog, {corpus} new to bootstrap_corpus")
    else:
        print("Usage: python -m bootstrap.cisa_kev [--download|--parse|--store]")
