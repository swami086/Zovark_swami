"""Parse MITRE ATT&CK STIX bundle into technique dicts."""

import json


def parse_mitre_stix(filepath: str) -> list:
    """Parse enterprise-attack.json STIX bundle.

    Returns list of dicts with: technique_id, name, description, tactics,
    platforms, data_sources, detection, url
    """
    with open(filepath, "r") as f:
        bundle = json.load(f)

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract external ID (e.g. T1110.003)
        ext_refs = obj.get("external_references", [])
        technique_id = None
        url = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break

        if not technique_id:
            continue

        # Extract tactics from kill_chain_phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": obj.get("x_mitre_detection", ""),
            "url": url or "",
        })

    return techniques
