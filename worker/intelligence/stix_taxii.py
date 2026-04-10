"""STIX/TAXII threat intel ingestion activity (Issue #37).

Parses STIX 2.1 bundles (indicators, malware, attack-patterns).
Stores in entities table with source="stix_feed".
Polls TAXII 2.1 endpoints for new bundles using httpx.AsyncClient (non-blocking HTTP).
DB access uses the shared ThreadedConnectionPool (database.pool_manager).
"""

import os
import json
import httpx
from temporalio import activity

from database.pool_manager import pooled_connection


def _get_db_cm():
    """Use shared pool for STIX ingest (avoid per-call connect)."""
    return pooled_connection("background")


# STIX object type to entity type mapping
STIX_TYPE_MAP = {
    "indicator": "indicator",
    "malware": "malware",
    "attack-pattern": "attack_pattern",
    "threat-actor": "threat_actor",
    "tool": "tool",
    "vulnerability": "vulnerability",
    "campaign": "campaign",
    "identity": "identity",
    "infrastructure": "infrastructure",
}


@activity.defn
async def ingest_threat_feed(data: dict) -> dict:
    """Parse and ingest a STIX 2.1 bundle into the entities table.

    Input: {
        bundle: dict (STIX 2.1 bundle JSON),
        tenant_id: optional,
        source_name: str (feed name for attribution)
    }
    Returns: {
        ingested: int, skipped: int, errors: int,
        types: {type: count}
    }
    """
    bundle = data.get("bundle", {})
    tenant_id = data.get("tenant_id")
    source_name = data.get("source_name", "stix_feed")

    objects = bundle.get("objects", [])
    if not objects:
        return {"ingested": 0, "skipped": 0, "errors": 0, "types": {}}

    ingested = 0
    skipped = 0
    errors = 0
    type_counts = {}

    with _get_db_cm() as conn:
        with conn.cursor() as cur:
            for obj in objects:
                stix_type = obj.get("type", "")
                entity_type = STIX_TYPE_MAP.get(stix_type)

                if not entity_type:
                    skipped += 1
                    continue

                try:
                    # Extract value/name based on STIX type
                    entity_value = _extract_stix_value(obj)
                    if not entity_value:
                        skipped += 1
                        continue

                    stix_id = obj.get("id", "")
                    description = obj.get("description", "")
                    created = obj.get("created", "")
                    modified = obj.get("modified", "")

                    # Build metadata
                    metadata = {
                        "source": source_name,
                        "stix_id": stix_id,
                        "stix_type": stix_type,
                        "description": description[:500] if description else "",
                        "created": created,
                        "modified": modified,
                    }

                    # Extract MITRE ATT&CK technique IDs from attack-pattern
                    if stix_type == "attack-pattern":
                        external_refs = obj.get("external_references", [])
                        for ref in external_refs:
                            if ref.get("source_name") == "mitre-attack":
                                metadata["mitre_id"] = ref.get("external_id", "")

                    # Extract IOC patterns from indicators
                    if stix_type == "indicator":
                        pattern = obj.get("pattern", "")
                        metadata["pattern"] = pattern
                        metadata["pattern_type"] = obj.get("pattern_type", "stix")
                        metadata["valid_from"] = obj.get("valid_from", "")
                        metadata["valid_until"] = obj.get("valid_until", "")

                    # Insert or update entity
                    cur.execute("""
                        INSERT INTO entities (value, type, tenant_id, first_seen, metadata)
                        VALUES (%s, %s, %s, NOW(), %s)
                        ON CONFLICT (value, type, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'))
                        DO UPDATE SET
                            metadata = entities.metadata || %s,
                            last_seen = NOW()
                        RETURNING id::text
                    """, (
                        entity_value,
                        entity_type,
                        tenant_id,
                        json.dumps(metadata),
                        json.dumps(metadata),
                    ))

                    ingested += 1
                    type_counts[entity_type] = type_counts.get(entity_type, 0) + 1

                except Exception as e:
                    errors += 1
                    print(f"stix_ingest: object {obj.get('id', '?')} failed: {e}")

        conn.commit()

    return {
        "ingested": ingested,
        "skipped": skipped,
        "errors": errors,
        "types": type_counts,
        "source": source_name,
    }


def _extract_stix_value(obj):
    """Extract the primary value from a STIX object."""
    stix_type = obj.get("type", "")

    if stix_type == "indicator":
        # Try to extract IOC from STIX pattern
        pattern = obj.get("pattern", "")
        # e.g., "[ipv4-addr:value = '192.168.1.1']"
        import re
        match = re.search(r"'([^']+)'", pattern)
        if match:
            return match.group(1)
        return obj.get("name", pattern[:200])

    if stix_type in ("malware", "attack-pattern", "tool", "campaign", "threat-actor"):
        return obj.get("name", obj.get("id", ""))

    if stix_type == "vulnerability":
        # Use CVE ID if available
        external_refs = obj.get("external_references", [])
        for ref in external_refs:
            if ref.get("source_name") == "cve":
                return ref.get("external_id", "")
        return obj.get("name", obj.get("id", ""))

    return obj.get("name", obj.get("id", ""))


@activity.defn
async def poll_taxii_server(data: dict) -> dict:
    """Poll a TAXII 2.1 server for threat intelligence bundles.

    Input: {
        taxii_url: str,
        collection_id: str,
        api_root: str (optional),
        username: str (optional),
        password: str (optional),
        tenant_id: str (optional),
        source_name: str
    }
    Returns: {
        status: str, bundles_fetched: int,
        total_objects: int, ingested: int
    }
    """
    taxii_url = data.get("taxii_url", "")
    collection_id = data.get("collection_id", "")
    api_root = data.get("api_root", "")
    username = data.get("username", os.environ.get("TAXII_USERNAME", ""))
    password = data.get("password", os.environ.get("TAXII_PASSWORD", ""))
    tenant_id = data.get("tenant_id")
    source_name = data.get("source_name", "taxii_feed")

    if not taxii_url or not collection_id:
        return {"status": "error", "message": "taxii_url and collection_id required"}

    # Build TAXII 2.1 collection URL
    if api_root:
        collection_url = f"{taxii_url}/{api_root}/collections/{collection_id}/objects/"
    else:
        collection_url = f"{taxii_url}/collections/{collection_id}/objects/"

    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }

    auth = None
    if username and password:
        auth = (username, password)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                collection_url,
                headers=headers,
                auth=auth,
            )
            resp.raise_for_status()
            response_data = resp.json()

        # TAXII 2.1 wraps objects in an envelope
        objects = response_data.get("objects", [])
        if not objects:
            return {
                "status": "completed",
                "bundles_fetched": 1,
                "total_objects": 0,
                "ingested": 0,
            }

        # Create a STIX bundle and ingest it
        bundle = {
            "type": "bundle",
            "id": f"bundle--taxii-{collection_id}",
            "objects": objects,
        }

        ingest_result = await ingest_threat_feed({
            "bundle": bundle,
            "tenant_id": tenant_id,
            "source_name": source_name,
        })

        return {
            "status": "completed",
            "bundles_fetched": 1,
            "total_objects": len(objects),
            "ingested": ingest_result.get("ingested", 0),
            "skipped": ingest_result.get("skipped", 0),
            "errors": ingest_result.get("errors", 0),
            "types": ingest_result.get("types", {}),
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)[:500],
            "bundles_fetched": 0,
            "total_objects": 0,
            "ingested": 0,
        }
