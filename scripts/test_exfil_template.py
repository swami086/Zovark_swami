"""Test data exfiltration template with strengthened raw_log."""
import json
import psycopg2

conn = psycopg2.connect("postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
with conn.cursor() as cur:
    cur.execute("SELECT code_template FROM agent_skills WHERE skill_slug = 'data-exfiltration-detection'")
    template = cur.fetchone()[0]
conn.close()

siem = {
    "raw_log": "23:47 rwilson compressed 47 GB to /tmp/.hidden/archive.7z then POST https://mega.nz/upload 4388 GB via HTTPS to 185.220.101.45:443. Content-Encoding: gzip encrypted. Total: 47312 MB in 8 min. Process: rclone.exe on WS-FIN-01",
    "source_ip": "10.0.1.50",
    "destination_ip": "185.220.101.45",
    "hostname": "WS-FIN-01",
    "username": "rwilson",
}

siem_json = json.dumps(siem)
val_str = siem_json.replace("\\", "\\\\").replace("'''", "\\'\\'\\'")
rendered = template.replace("{{siem_event_json}}", val_str)

exec(rendered)
