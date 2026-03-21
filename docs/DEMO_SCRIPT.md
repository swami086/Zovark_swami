# HYDRA Demo Script (2 minutes)

## Setup (before demo)
1. Ensure all services running: `docker compose ps`
2. Start dashboard: `cd dashboard && npx vite --port 5173`
3. Verify LLM: `curl http://localhost:11434/v1/models`
4. Login credentials: `admin@test.local` / `TestPass2026`

## Demo Flow

### Scene 1: The Problem (15 seconds)
"SOC teams process thousands of alerts daily. 70% are false positives.
Tier 1 analysts spend 30-60 minutes per investigation.
HYDRA does it in under 60 seconds."

### Scene 2: Dashboard (20 seconds)
- Open http://localhost:5173
- Login with admin@test.local
- Show: 350+ total investigations, 280+ resolved
- "HYDRA has already processed 350 security alerts autonomously"

### Scene 3: Live Investigation (60 seconds)
- Submit a phishing alert via curl or the New Investigation page
- Watch it appear in the queue as "pending"
- Watch status change to "running" (pipeline executing)
- Watch it complete with verdict
- "37 seconds. Phishing detected. IOCs extracted. Recommendations generated."

### Scene 4: Investigation Detail (30 seconds)
- Click into the completed investigation
- Show: Verdict badge, Risk score (85), LLM-generated summary
- Show: Extracted IOCs (domains like micros0ft-365.com, IPs)
- Show: Recommendations (purge email, block domains)
- "All of this happened on-premise. Zero data left your network."

### Scene 5: Close (15 seconds)
"HYDRA investigates like a senior analyst at Tier 1 speed.
Air-gapped. On-premise. No data leaves your network.
We're looking for 3 design partners. Interested?"

## Quick Submit Commands

```bash
# Phishing (best demo — always produces findings)
curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"phishing_investigation","input":{"prompt":"Investigate phishing email","severity":"high","siem_event":{"title":"Phishing Email","source_ip":"10.0.0.42","destination_ip":"203.0.113.50","hostname":"WS-ANALYST-07","username":"jsmith","rule_name":"Phishing_URL","raw_log":"From: support@micros0ft-365.com To: jsmith Subject: Password Expiry URL: https://micros0ft-365.com/login"}}}'

# Ransomware (highest risk score — 95)
curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"ransomware_triage","input":{"prompt":"Investigate ransomware","severity":"critical","siem_event":{"title":"Ransomware","source_ip":"10.0.0.75","destination_ip":"10.0.0.100","hostname":"FILE-SERVER-01","username":"bob","rule_name":"Ransomware","raw_log":"vssadmin Delete Shadows /All. FileRename report.xlsx to report.xlsx.locked. MD5=a1b2c3d4e5f67890abcdef1234567890"}}}'
```
