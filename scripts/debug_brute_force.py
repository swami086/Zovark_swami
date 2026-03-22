"""Debug brute force template rendering."""
import json
import psycopg2

DATABASE_URL = "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"

# Simulate the SIEM event from the test
siem_event = {
    "title": "SSH brute force",
    "source_ip": "45.33.32.156",
    "destination_ip": "10.0.0.5",
    "hostname": "DC-01",
    "username": "root",
    "rule_name": "BruteForce",
    "raw_log": "Mar 22 07:10:01 DC-01 sshd[12345]: Failed password for root from 45.33.32.156 port 44832 ssh2\nMar 22 07:10:02 DC-01 sshd[12346]: Failed password for admin from 45.33.32.156 port 44833 ssh2"
}

# Get the template from DB
conn = psycopg2.connect(DATABASE_URL)
with conn.cursor() as cur:
    cur.execute("SELECT code_template FROM agent_skills WHERE skill_slug = 'brute-force-investigation'")
    template = cur.fetchone()[0]
conn.close()

# Simulate _fill_parameters_fast
siem_event_json = json.dumps(siem_event)
print("=== siem_event_json (first 200 chars) ===")
print(repr(siem_event_json[:200]))

# Simulate _render_template
val_str = siem_event_json.replace('\\', '\\\\').replace("'''", "\\'\\'\\'")
print("\n=== escaped (first 200 chars) ===")
print(repr(val_str[:200]))

rendered = template.replace("{{siem_event_json}}", val_str)
print("\n=== rendered code (first 500 chars) ===")
print(rendered[:500])

# Try to parse
print("\n=== Attempting to compile ===")
try:
    compile(rendered, "<template>", "exec")
    print("COMPILE: OK")
except SyntaxError as e:
    print(f"COMPILE ERROR: {e}")

# Try to execute
print("\n=== Attempting to exec ===")
try:
    exec(rendered)
except Exception as e:
    print(f"EXEC ERROR: {type(e).__name__}: {e}")
