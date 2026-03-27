import psycopg2

conn = psycopg2.connect("postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
cur = conn.cursor()

to_update = [
    ("ransomware-triage", "/app/tests/ransomware-triage.py"),
    ("c2-communication-hunt", "/app/tests/c2-communication-hunt.py"),
    ("phishing-investigation", "/app/tests/phishing-investigation.py")
]

for slug, filepath in to_update:
    with open(filepath, "r") as f:
        code = f.read()
    cur.execute("UPDATE agent_skills SET code_template = %s WHERE skill_slug = %s", (code, slug))
    
conn.commit()
print("Database templates updated!")
