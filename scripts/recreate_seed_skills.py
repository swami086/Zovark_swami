import os
import json
import psycopg2
import urllib.request
import urllib.error

DB_URL = os.getenv("POSTGRES_URI", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")

with open('/app/seed_skills.py', 'r') as f:
    content = f.read()

namespace = {}
exec(content, namespace)
UPDATES = namespace.get("UPDATES", [])

def get_embedding(text):
    try:
        req = urllib.request.Request('http://embedding-server:80/embed', json.dumps({'inputs': text}).encode(), {'Content-Type': 'application/json'})
        r = urllib.request.urlopen(req)
        data = json.loads(r.read())
        if isinstance(data, list) and len(data) > 0:
            return data[0] if isinstance(data[0], list) else data
    except Exception as e:
        print(f"Embedding failed: {e}")
    return [0.0]*768

def main():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    
    cur.execute("SELECT id FROM tenants LIMIT 1")
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO tenants (name) VALUES ('Test Tenant') RETURNING id")
        tenant_id = cur.fetchone()[0]
    else:
        tenant_id = row[0]
        
    for slug, template, params in UPDATES:
        name = slug.replace("-", " ").title()
        threat_type = slug.replace("-", "_")
        embedding = get_embedding(name)
        
        cur.execute("""
            INSERT INTO agent_skills (
                tenant_id, skill_name, skill_slug, threat_types, mitre_tactics, mitre_techniques, keywords,
                investigation_methodology, detection_patterns, example_prompt, times_used, embedding, is_active, version, code_template, parameters
            ) VALUES (
                %s, %s, %s, ARRAY[%s]::varchar[], '{}', '{}', ARRAY[%s]::varchar[], 'Generic methodology', 'Generic patterns', 'Investigate', 0, %s::vector, true, 1, %s, %s::jsonb
            ) ON CONFLICT (tenant_id, skill_slug, version) DO UPDATE SET 
                code_template = EXCLUDED.code_template, parameters = EXCLUDED.parameters, embedding = EXCLUDED.embedding, is_active = true;
        """, (tenant_id, name, slug, threat_type, name.lower(), embedding, template, json.dumps(params)))
        print(f"Inserted/Updated: {slug}")
        
    conn.commit()
    print("Done inserting all 10 skills.")

if __name__ == "__main__":
    main()
