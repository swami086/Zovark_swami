#!/usr/bin/env python3
"""Fix all 11 skill templates: convert IOC format from dict to list-of-dicts."""
import psycopg2
import re

DATABASE_URL = "postgresql://hydra:hydra_dev_2026@localhost:5432/hydra"

# The IOC conversion snippet to inject before `print(json.dumps(output`
IOC_CONVERSION = '''
# === Convert IOCs to structured list format ===
ioc_list = []
if isinstance(iocs, dict):
    for ip in iocs.get("ips", []):
        ioc_list.append({"type": "ip", "value": ip, "severity": "high", "confidence": "high"})
    for d in iocs.get("domains", []):
        ioc_list.append({"type": "domain", "value": d, "severity": "high", "confidence": "high"})
    for h in iocs.get("hashes", []):
        ioc_list.append({"type": "hash", "value": h, "severity": "medium", "confidence": "medium"})
    for e in iocs.get("emails", []):
        ioc_list.append({"type": "email", "value": e, "severity": "medium", "confidence": "high"})
elif isinstance(iocs, list):
    ioc_list = iocs
'''


def fix_template(template: str) -> str:
    """Fix a single template's IOC output format."""
    # Strategy: find the output = { ... } block and replace "iocs": <old> with "iocs": ioc_list
    # Also inject the IOC conversion before the output block

    # Find where `output = {` starts
    output_match = re.search(r'^output\s*=\s*\{', template, re.MULTILINE)
    if not output_match:
        print("  WARNING: No 'output = {' found in template")
        return template

    # Inject IOC conversion before the output block
    insert_pos = output_match.start()
    template = template[:insert_pos] + IOC_CONVERSION + "\n" + template[insert_pos:]

    # Now replace the old iocs format in the output dict
    # Pattern: "iocs": {"ips": ..., "domains": ..., "hashes": ...}
    # or "iocs": iocs
    template = re.sub(
        r'"iocs"\s*:\s*\{[^}]*\}',
        '"iocs": ioc_list',
        template
    )
    # Also handle "iocs": iocs (direct reference)
    template = re.sub(
        r'"iocs"\s*:\s*iocs(?!\s*_)',
        '"iocs": ioc_list',
        template
    )

    return template


def main():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # Get all templates
    cur.execute("SELECT id, skill_slug, code_template FROM agent_skills WHERE is_active = true ORDER BY skill_slug")
    rows = cur.fetchall()

    for skill_id, slug, template in rows:
        if not template:
            print(f"  SKIP {slug}: no template")
            continue

        print(f"Fixing {slug}...")
        fixed = fix_template(template)

        if fixed != template:
            cur.execute("UPDATE agent_skills SET code_template = %s, updated_at = NOW() WHERE id = %s",
                       (fixed, skill_id))
            print(f"  UPDATED {slug}")
        else:
            print(f"  NO CHANGE {slug}")

    # Also fix network-beaconing threat_types to include network_beaconing
    cur.execute("""
        UPDATE agent_skills
        SET threat_types = array_append(threat_types, 'network_beaconing')
        WHERE skill_slug = 'network-beaconing'
        AND NOT ('network_beaconing' = ANY(threat_types))
    """)
    if cur.rowcount > 0:
        print("\nFixed network-beaconing threat_types: added 'network_beaconing'")

    conn.commit()
    cur.close()
    conn.close()
    print("\nDone! All templates updated.")


if __name__ == "__main__":
    main()
