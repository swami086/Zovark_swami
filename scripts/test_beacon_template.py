"""Test beaconing template with actual corpus data."""
import json
import psycopg2

conn = psycopg2.connect("postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
with conn.cursor() as cur:
    cur.execute("SELECT code_template FROM agent_skills WHERE skill_slug = 'network-beaconing'")
    template = cur.fetchone()[0]
conn.close()

siem = {
    "raw_log": "10:00:00 WS-HR-01 HTTPS -> 185.220.101.45:443 size=1024\n10:01:00 WS-HR-01 HTTPS -> 185.220.101.45:443 size=1028\n10:02:01 WS-HR-01 HTTPS -> 185.220.101.45:443 size=1024",
    "source_ip": "192.168.1.55",
    "destination_ip": "185.220.101.45",
    "hostname": "WS-01",
    "username": "jsmith",
}

# Simulate _render_template
siem_json = json.dumps(siem)
val_str = siem_json.replace("\\", "\\\\").replace("'''", "\\'\\'\\'")
rendered = template.replace("{{siem_event_json}}", val_str)

print("First 200 chars of rendered:")
print(rendered[:200])
print()

# Check what json.loads sees
import re
match = re.search(r'json\.loads\("""(.+?)"""\)', rendered, re.DOTALL)
if match:
    json_str = match.group(1)
    print(f"JSON string length: {len(json_str)}")
    print(f"JSON string first 100: {repr(json_str[:100])}")
    try:
        parsed = json.loads(json_str)
        raw_log = parsed.get("raw_log", "")
        print(f"raw_log: {repr(raw_log[:100])}")
        timestamps = re.findall(r'(\d{2}):(\d{2}):(\d{2})', raw_log)
        print(f"Timestamps found: {len(timestamps)}")
    except Exception as e:
        print(f"JSON parse error: {e}")
else:
    print("Could not find json.loads in rendered code")

# Run the full template
print("\n=== EXECUTING TEMPLATE ===")
try:
    exec(rendered)
except Exception as e:
    print(f"EXEC ERROR: {type(e).__name__}: {e}")
