"""Debug the JSON escaping chain for siem_event_json."""
import json
import re

# Simulate SIEM event with newlines in raw_log
siem = {
    "raw_log": "10:00:00 WS-01 HTTPS -> 1.2.3.4:443 size=1024\n10:01:00 WS-01 HTTPS -> 1.2.3.4:443 size=1028\n10:02:01 WS-01 HTTPS -> 1.2.3.4:443 size=1024",
    "source_ip": "192.168.1.55",
    "destination_ip": "185.220.101.45",
}

# Step 1: json.dumps (what _fill_parameters_fast does)
siem_json = json.dumps(siem)
print("1. json.dumps result (first 120):")
print(f"   {repr(siem_json[:120])}")

# Step 2: _render_template escaping
val_str = siem_json.replace("\\", "\\\\").replace("'''", "\\'\\'\\'")
print("\n2. After _render_template escape (first 120):")
print(f"   {repr(val_str[:120])}")

# Step 3: What the template code looks like
template_line = f'siem_event = json.loads("""{val_str}""")'
print(f"\n3. Template line (first 120):")
print(f"   {repr(template_line[:120])}")

# Step 4: Execute it and see what raw_log looks like
exec_env = {"json": json}
exec(f"import json\n{template_line}", exec_env)
parsed_siem = exec_env["siem_event"]
raw_log = parsed_siem["raw_log"]
print(f"\n4. Parsed raw_log (first 120):")
print(f"   {repr(raw_log[:120])}")

# Step 5: Check timestamps
timestamps = re.findall(r'(\d{2}):(\d{2}):(\d{2})', raw_log)
print(f"\n5. Timestamps found: {len(timestamps)}")
print(f"   {timestamps}")

# The problem: does \n become actual newline or literal \\n?
nl = "\n"
has_nl = nl in raw_log
print(f"\n6. Contains actual newline: {has_nl}")
print(f"   repr sample: {repr(raw_log[:60])}")
