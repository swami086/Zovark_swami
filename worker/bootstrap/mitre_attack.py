"""MITRE ATT&CK Enterprise ingestion — download, parse, store.

Air-gap support: checks for bundled file at /app/bootstrap_data/enterprise-attack.json
before attempting download. Falls back to download from GitHub if bundled file is missing.

Usage as Temporal activity (registered in bootstrap workflow) or standalone:
    python -m bootstrap.mitre_attack --download  # download only
    python -m bootstrap.mitre_attack --parse     # parse bundled file
"""

import os
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

# Air-gap bundle paths (checked in order)
BUNDLE_PATHS = [
    "/app/bootstrap_data/enterprise-attack.json",
    "/app/bootstrap_data/mitre/enterprise-attack.json",
    os.path.join(os.path.dirname(__file__), "data", "enterprise-attack.json"),
]


def find_bundled_stix() -> Optional[str]:
    """Find a bundled MITRE ATT&CK STIX file. Returns path or None."""
    for path in BUNDLE_PATHS:
        if os.path.isfile(path):
            logger.info("Found bundled MITRE STIX at %s", path)
            return path
    return None


def download_stix(dest_path: Optional[str] = None) -> str:
    """Download MITRE ATT&CK Enterprise STIX bundle.

    Args:
        dest_path: Where to save. Defaults to a temp file.

    Returns:
        Path to downloaded file.

    Raises:
        RuntimeError: If download fails.
    """
    import httpx

    if dest_path is None:
        dest_path = os.path.join(tempfile.gettempdir(), "enterprise-attack.json")

    logger.info("Downloading MITRE ATT&CK STIX from %s", MITRE_STIX_URL)
    try:
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            resp = client.get(MITRE_STIX_URL)
            resp.raise_for_status()
            Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
            with open(dest_path, "wb") as f:
                f.write(resp.content)
        logger.info("Downloaded MITRE STIX to %s (%d bytes)", dest_path, os.path.getsize(dest_path))
        return dest_path
    except Exception as e:
        raise RuntimeError(f"Failed to download MITRE ATT&CK STIX: {e}") from e


def resolve_stix_path() -> str:
    """Resolve STIX path: bundled file first, then download.

    Returns:
        Path to STIX JSON file.

    Raises:
        RuntimeError: If neither bundled nor download succeeds.
    """
    bundled = find_bundled_stix()
    if bundled:
        return bundled

    logger.info("No bundled STIX file found, attempting download")
    return download_stix()


def parse_stix_bundle(filepath: str) -> dict:
    """Parse MITRE ATT&CK STIX bundle into structured data.

    Returns dict with:
        techniques: list of technique dicts
        software: list of software dicts
        groups: list of group dicts
        relationships: list of relationship dicts (procedure examples)
    """
    with open(filepath, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # Index by STIX ID for relationship resolution
    stix_index = {}
    for obj in objects:
        stix_id = obj.get("id", "")
        if stix_id:
            stix_index[stix_id] = obj

    techniques = []
    software = []
    groups = []
    relationships = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        if obj_type == "attack-pattern":
            techniques.append(_parse_technique(obj))
        elif obj_type == "malware" or obj_type == "tool":
            software.append(_parse_software(obj))
        elif obj_type == "intrusion-set":
            groups.append(_parse_group(obj))
        elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
            rel = _parse_relationship(obj, stix_index)
            if rel:
                relationships.append(rel)

    logger.info(
        "Parsed MITRE STIX: %d techniques, %d software, %d groups, %d relationships",
        len(techniques), len(software), len(groups), len(relationships),
    )
    return {
        "techniques": techniques,
        "software": software,
        "groups": groups,
        "relationships": relationships,
    }


def _extract_external_id(obj: dict) -> tuple:
    """Extract MITRE external ID and URL from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", ""), ref.get("url", "")
    return "", ""


def _parse_technique(obj: dict) -> dict:
    technique_id, url = _extract_external_id(obj)
    if not technique_id:
        return {}

    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase["phase_name"])

    return {
        "technique_id": technique_id,
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "tactics": tactics,
        "platforms": obj.get("x_mitre_platforms", []),
        "data_sources": obj.get("x_mitre_data_sources", []),
        "detection_hints": obj.get("x_mitre_detection", ""),
        "url": url,
        "stix_id": obj.get("id", ""),
    }


def _parse_software(obj: dict) -> dict:
    ext_id, url = _extract_external_id(obj)
    return {
        "software_id": ext_id,
        "name": obj.get("name", ""),
        "description": obj.get("description", "")[:500],
        "type": obj.get("type", ""),
        "platforms": obj.get("x_mitre_platforms", []),
        "stix_id": obj.get("id", ""),
    }


def _parse_group(obj: dict) -> dict:
    ext_id, url = _extract_external_id(obj)
    return {
        "group_id": ext_id,
        "name": obj.get("name", ""),
        "description": obj.get("description", "")[:500],
        "aliases": obj.get("aliases", []),
        "stix_id": obj.get("id", ""),
    }


def _parse_relationship(obj: dict, stix_index: dict) -> Optional[dict]:
    """Parse a 'uses' relationship (procedure example)."""
    source_ref = obj.get("source_ref", "")
    target_ref = obj.get("target_ref", "")
    description = obj.get("description", "")

    source_obj = stix_index.get(source_ref, {})
    target_obj = stix_index.get(target_ref, {})

    source_id, _ = _extract_external_id(source_obj)
    target_id, _ = _extract_external_id(target_obj)

    if not source_id or not target_id:
        return None

    return {
        "source_id": source_id,
        "source_name": source_obj.get("name", ""),
        "source_type": source_obj.get("type", ""),
        "target_id": target_id,
        "target_name": target_obj.get("name", ""),
        "target_type": target_obj.get("type", ""),
        "description": description[:500] if description else "",
    }


def store_techniques(techniques: list, db_url: str = "") -> int:
    """Batch upsert techniques into mitre_techniques table.

    Returns number of techniques upserted.
    """
    import psycopg2
    from psycopg2.extras import execute_values

    if not db_url:
        db_url = os.environ.get(
            "DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
        )

    valid = [t for t in techniques if t.get("technique_id")]
    if not valid:
        return 0

    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            values = [
                (
                    t["technique_id"],
                    t["name"],
                    t["description"],
                    t["tactics"],
                    t["platforms"],
                    t["data_sources"],
                    t.get("detection_hints", ""),
                    t.get("url", ""),
                )
                for t in valid
            ]
            execute_values(
                cur,
                """INSERT INTO mitre_techniques
                   (technique_id, name, description, tactics, platforms,
                    data_sources, detection_hints, url, last_synced)
                   VALUES %s
                   ON CONFLICT (technique_id) DO UPDATE SET
                       name = EXCLUDED.name,
                       description = EXCLUDED.description,
                       tactics = EXCLUDED.tactics,
                       platforms = EXCLUDED.platforms,
                       data_sources = EXCLUDED.data_sources,
                       detection_hints = EXCLUDED.detection_hints,
                       url = EXCLUDED.url,
                       last_synced = NOW()""",
                values,
                template="(%s, %s, %s, %s, %s, %s, %s, %s)",
            )
        conn.commit()
        logger.info("Upserted %d MITRE techniques", len(valid))
        return len(valid)
    finally:
        conn.close()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if "--download" in sys.argv:
        dest = download_stix()
        print(f"Downloaded to: {dest}")
    elif "--parse" in sys.argv:
        path = resolve_stix_path()
        result = parse_stix_bundle(path)
        print(f"Techniques: {len(result['techniques'])}")
        print(f"Software: {len(result['software'])}")
        print(f"Groups: {len(result['groups'])}")
        print(f"Relationships: {len(result['relationships'])}")
    else:
        print("Usage: python -m bootstrap.mitre_attack [--download|--parse]")
