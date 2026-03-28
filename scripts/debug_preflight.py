"""Debug preflight validation for brute force template."""
import json
import psycopg2
from validation.preflight import preflight_validate, auto_fix_code

conn = psycopg2.connect("postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
with conn.cursor() as cur:
    cur.execute("SELECT code_template FROM agent_skills WHERE skill_slug = 'brute-force-investigation'")
    template = cur.fetchone()[0]
conn.close()

siem = {
    "raw_log": "Failed password for root from 45.33.32.156\nAccepted password",
    "source_ip": "45.33.32.156",
    "destination_ip": "10.0.0.5",
    "hostname": "DC-01",
    "username": "root",
    "rule_name": "BF"
}

siem_json = json.dumps(siem)
# Simulate _render_template escaping
val_str = siem_json.replace("\\", "\\\\").replace("'''", "\\'\\'\\'")
rendered = template.replace("{{siem_event_json}}", val_str)

print("=== Code length:", len(rendered))
print("=== First 200 chars:")
print(rendered[:200])

fixed, fixes = auto_fix_code(rendered)
print("\n=== auto_fix_code fixes:", fixes)

is_valid, cleaned, warnings = preflight_validate(fixed)
print("\n=== Preflight valid:", is_valid)
print("=== Warnings:", warnings)
if not is_valid:
    print("=== Error:", cleaned)
else:
    # Try AST check from execute stage
    import ast, re
    try:
        tree = ast.parse(fixed)
        print("=== AST parse: OK")
    except SyntaxError as e:
        print(f"=== AST parse error: {e}")

    # Try executing
    print("\n=== Executing...")
    exec(fixed)
