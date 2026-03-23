#!/bin/bash
# HYDRA Demo — 2-min walkthrough for CISO audience
# Shows: alert in → investigation → IOCs extracted → verdict delivered
set -e

API="http://localhost:8090"
MAX_WAIT=120  # seconds to wait for investigations to complete

echo "=== HYDRA Autonomous SOC — Live Demo ==="
echo ""

# Login
TOKEN=$(curl -s -X POST $API/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' \
  | sed 's/.*"token":"\([^"]*\)".*/\1/')
echo "Authenticated."
echo ""

# Scene 1: Brute Force
echo "=== SCENE 1: SSH Brute Force Alert ==="
echo "Submitting: 500 failed SSH logins from 185.220.101.45 targeting root..."
BF_RESP=$(curl -s -X POST $API/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"task_type":"brute_force","input":{"prompt":"SSH brute force from Eastern Europe","severity":"critical","siem_event":{"title":"SSH Brute Force - 500 attempts in 60s","source_ip":"185.220.101.45","destination_ip":"10.0.0.5","hostname":"prod-server-01","username":"root","rule_name":"BruteForce_Critical","raw_log":"Jan 15 03:22:11 prod-server-01 sshd[1234]: 500 failed password attempts for root from 185.220.101.45 in 60s. Account locked."}}}')
BF_ID=$(echo "$BF_RESP" | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
echo "  Task ID: $BF_ID"
echo ""

# Scene 2: Lateral Movement
echo "=== SCENE 2: Lateral Movement - Pass the Hash ==="
echo "Submitting: mimikatz.exe detected moving from finance workstation to domain controller..."
LM_RESP=$(curl -s -X POST $API/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"task_type":"lateral_movement","input":{"prompt":"Pass-the-Hash from finance to DC","severity":"critical","siem_event":{"title":"Lateral Movement - Pass the Hash","source_ip":"10.0.0.50","destination_ip":"10.0.0.200","hostname":"WS-FINANCE-03","username":"svc_backup","rule_name":"PtH_Detected","raw_log":"EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY.corp.local User=svc_backup NTLM_hash=aad3b435b51404eeaad3b435b51404ee ParentProcess=mimikatz.exe"}}}')
LM_ID=$(echo "$LM_RESP" | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
echo "  Task ID: $LM_ID"
echo ""

# Poll until both complete or timeout
echo "=== Investigating... ==="
ELAPSED=0
BF_DONE=0
LM_DONE=0
while [ $ELAPSED -lt $MAX_WAIT ] && ([ $BF_DONE -eq 0 ] || [ $LM_DONE -eq 0 ]); do
  sleep 5
  ELAPSED=$((ELAPSED + 5))

  if [ $BF_DONE -eq 0 ]; then
    BF_STATUS=$(curl -s "$API/api/v1/tasks/$BF_ID" -H "Authorization: Bearer $TOKEN" \
      | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
    if [ "$BF_STATUS" = "completed" ] || [ "$BF_STATUS" = "failed" ]; then
      BF_DONE=1
      echo "  [${ELAPSED}s] Brute Force: $BF_STATUS"
    fi
  fi

  if [ $LM_DONE -eq 0 ]; then
    LM_STATUS=$(curl -s "$API/api/v1/tasks/$LM_ID" -H "Authorization: Bearer $TOKEN" \
      | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
    if [ "$LM_STATUS" = "completed" ] || [ "$LM_STATUS" = "failed" ]; then
      LM_DONE=1
      echo "  [${ELAPSED}s] Lateral Movement: $LM_STATUS"
    fi
  fi

  if [ $BF_DONE -eq 0 ] && [ $LM_DONE -eq 0 ]; then
    echo "  [${ELAPSED}s] Both still running..."
  elif [ $BF_DONE -eq 0 ]; then
    echo "  [${ELAPSED}s] Brute Force still running..."
  elif [ $LM_DONE -eq 0 ]; then
    echo "  [${ELAPSED}s] Lateral Movement still running..."
  fi

  # Refresh token every 60s to avoid expiry
  if [ $((ELAPSED % 60)) -eq 0 ] && [ $ELAPSED -gt 0 ]; then
    TOKEN=$(curl -s -X POST $API/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d '{"email":"admin@test.local","password":"TestPass2026"}' \
      | sed 's/.*"token":"\([^"]*\)".*/\1/')
  fi
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
  echo "  (timed out after ${MAX_WAIT}s — showing partial results)"
fi

# Refresh token for final fetch
TOKEN=$(curl -s -X POST $API/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' \
  | sed 's/.*"token":"\([^"]*\)".*/\1/')

# Results
echo ""
echo "=== RESULTS ==="
echo ""

for LABEL_ID in "Brute Force:$BF_ID" "Lateral Movement:$LM_ID"; do
  LABEL=$(echo "$LABEL_ID" | cut -d: -f1)
  ID=$(echo "$LABEL_ID" | cut -d: -f2)
  RESULT=$(curl -s "$API/api/v1/tasks/$ID" -H "Authorization: Bearer $TOKEN")
  STATUS=$(echo "$RESULT" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
  VERDICT=$(echo "$RESULT" | sed -n 's/.*"verdict":"\([^"]*\)".*/\1/p' | head -1)
  RISK=$(echo "$RESULT" | sed -n 's/.*"risk_score":\([0-9]*\).*/\1/p' | head -1)
  echo "--- $LABEL ---"
  echo "  Status:  $STATUS"
  echo "  Verdict: $VERDICT"
  echo "  Risk:    $RISK/100"
  echo ""
done

echo "=== Demo complete. Dashboard: http://localhost:3000 ==="
