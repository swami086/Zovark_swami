import os
import json
import psycopg2
import urllib.request

DB_URL = "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"

def main():
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        
        # Get real embedding
        req = urllib.request.Request('http://embedding-server:80/embed', json.dumps({'inputs': 'brute_force'}).encode(), {'Content-Type': 'application/json'})
        r = urllib.request.urlopen(req)
        emb_data = json.loads(r.read())
        embedding = emb_data[0] if isinstance(emb_data, list) else [0.0]*768
        
        slug = "brute-force-investigation"
        template = """import json, re

LOG_DATA = '''{{log_data}}'''
MAX_FAILURES = {{max_failures}}

findings = []
iocs = {"ips": ["192.168.1.100"], "domains": [], "hashes": []}
risk_score = 80

output = {
    "findings": [{"title": "Brute Force", "details": "Found issues in VPN portal log"}],
    "iocs": iocs,
    "recommendations": ["Block IP", "Reset user passwords"],
    "risk_score": risk_score,
    "follow_up_needed": False,
    "follow_up_prompt": ""
}
print(json.dumps(output, indent=2))
"""
        params = [{"name": "log_data", "type": "string", "default": ""}, {"name": "max_failures", "type": "integer", "default": 10}]
        
        cur.execute("SELECT id FROM tenants LIMIT 1;")
        tenant_id = cur.fetchone()[0]
        cur.execute("""
            INSERT INTO agent_skills (
                tenant_id, skill_name, skill_slug, threat_types, mitre_tactics, mitre_techniques, keywords, investigation_methodology, detection_patterns, example_prompt, times_used, embedding, is_active, version, code_template, parameters
            ) VALUES (
                %s, 'Brute Force Investigation', %s, '{brute_force}', '{}', '{}', '{failed_login}', '...', '...', 'prompt', 0, %s::vector, true, 1, %s, %s::jsonb
            ) ON CONFLICT (tenant_id, skill_slug, version) DO UPDATE SET code_template = EXCLUDED.code_template, parameters = EXCLUDED.parameters;
        """, (tenant_id, slug, embedding, template, json.dumps(params)))
        conn.commit()
        print("Inserted test skill!")
    except Exception as e:
        print("Failed:", e)

if __name__ == "__main__":
    main()
