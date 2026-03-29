#!/bin/bash
# =============================================================================
# ZOVARK Update Validation — Quick Suite (4 tests, ~60 seconds)
# =============================================================================
#
# Fast smoke test after platform updates. Runs 4 investigations:
#   2 attack scenarios  → must return risk >= 50
#   2 benign scenarios  → must return risk <= 35, verdict = benign
#
# Uses template-routed tests only (Path A ~350ms each) for speed.
#
# Prerequisites:
#   - All core Docker services running (docker compose up -d)
#   - Ollama serving qwen2.5:14b on host port 11434
#
# Usage:
#   bash scripts/validate_update_quick.sh
#
# Exit codes:
#   0 = ALL PASSED
#   1 = ONE OR MORE FAILED
# =============================================================================

set -euo pipefail

API="http://localhost:8090"
MAX_WAIT=120
POLL_INTERVAL=5
PASSED=0
FAILED=0
TOTAL=4

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Helpers
# =============================================================================

get_token() {
  curl -s -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@test.local","password":"TestPass2026"}' \
    | sed 's/.*"token":"\([^"]*\)".*/\1/'
}

submit_task() {
  curl -s -X POST "$API/api/v1/tasks" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$1" \
    | sed 's/.*"task_id":"\([^"]*\)".*/\1/'
}

poll_task() {
  local TASK_ID="$1"
  local ELAPSED=0
  local BODY=""
  local STATUS=""

  while [ $ELAPSED -lt $MAX_WAIT ]; do
    BODY=$(curl -s "$API/api/v1/tasks/$TASK_ID" \
      -H "Authorization: Bearer $TOKEN")
    STATUS=$(echo "$BODY" | grep -o '"status":"[^"]*"' | head -1 | sed 's/"status":"//;s/"//')

    if [ "$STATUS" != "pending" ] && [ "$STATUS" != "executing" ]; then
      echo "$BODY"
      return 0
    fi

    sleep $POLL_INTERVAL
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
  done

  echo "$BODY"
  return 1
}

extract_risk() {
  echo "$1" | grep -o '"risk_score":[0-9]*' | head -1 | sed 's/"risk_score"://'
}

extract_verdict() {
  echo "$1" | grep -o '"verdict":"[^"]*"' | head -1 | sed 's/"verdict":"//;s/"//'
}

# =============================================================================
# Pre-flight
# =============================================================================

echo ""
echo -e "${CYAN}===========================================${NC}"
echo -e "${CYAN}  ZOVARK Quick Validation (4 tests)${NC}"
echo -e "${CYAN}===========================================${NC}"
echo ""

HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$API/health" 2>/dev/null || echo "000")
if [ "$HEALTH" != "200" ]; then
  echo -e "${RED}ERROR: API not reachable at $API (HTTP $HEALTH)${NC}"
  exit 1
fi
echo -e "${GREEN}API healthy${NC}"

TOKEN=$(get_token)
if [ -z "$TOKEN" ] || [ ${#TOKEN} -lt 20 ]; then
  echo -e "${RED}ERROR: Failed to obtain auth token${NC}"
  exit 1
fi
echo -e "${GREEN}Authenticated${NC}"
echo ""

START_TIME=$(date +%s)

# =============================================================================
# Test 1: Brute Force (attack)
# =============================================================================

echo -e "${YELLOW}[1/4] SSH Brute Force (attack)${NC}"
TASK_ID=$(submit_task '{
  "task_type":"brute_force",
  "input":{
    "prompt":"SSH brute force attack",
    "severity":"high",
    "siem_event":{
      "title":"SSH Brute Force",
      "source_ip":"185.220.101.45",
      "destination_ip":"10.0.0.5",
      "hostname":"WEB-01",
      "username":"root",
      "rule_name":"BruteForce",
      "raw_log":"Failed password for root from 185.220.101.45 port 22 ssh2\nFailed password for root from 185.220.101.45 port 22 ssh2\nFailed password for admin from 185.220.101.45 port 22 ssh2"
    }
  }
}')
echo "  Task: $TASK_ID"
BODY=$(poll_task "$TASK_ID")
RISK=$(extract_risk "$BODY"); RISK=${RISK:-0}
VERDICT=$(extract_verdict "$BODY"); VERDICT=${VERDICT:-unknown}
echo "  Risk: $RISK | Verdict: $VERDICT"
if [ "$RISK" -ge 50 ] 2>/dev/null && echo "$VERDICT" | grep -qiE "suspicious|true_positive|malicious"; then
  echo -e "  ${GREEN}PASS${NC}"
  PASSED=$((PASSED + 1))
else
  echo -e "  ${RED}FAIL${NC} (expected risk>=50, got $RISK/$VERDICT)"
  FAILED=$((FAILED + 1))
fi

# =============================================================================
# Test 2: Ransomware (attack)
# =============================================================================

echo -e "${YELLOW}[2/4] Ransomware (attack)${NC}"
TASK_ID=$(submit_task '{
  "task_type":"ransomware",
  "input":{
    "prompt":"Ransomware encryption detected",
    "severity":"critical",
    "siem_event":{
      "title":"Ransomware Encryption",
      "source_ip":"10.0.0.75",
      "destination_ip":"10.0.0.100",
      "hostname":"FILE-SVR",
      "username":"bob",
      "rule_name":"Ransomware_Detected",
      "raw_log":"FileRename: doc.docx -> doc.docx.encrypted\nFileRename: data.xlsx -> data.xlsx.encrypted\nProcess=locker.exe MD5=abc123\nvssadmin delete shadows /all /quiet"
    }
  }
}')
echo "  Task: $TASK_ID"
BODY=$(poll_task "$TASK_ID")
RISK=$(extract_risk "$BODY"); RISK=${RISK:-0}
VERDICT=$(extract_verdict "$BODY"); VERDICT=${VERDICT:-unknown}
echo "  Risk: $RISK | Verdict: $VERDICT"
if [ "$RISK" -ge 50 ] 2>/dev/null && echo "$VERDICT" | grep -qiE "suspicious|true_positive|malicious"; then
  echo -e "  ${GREEN}PASS${NC}"
  PASSED=$((PASSED + 1))
else
  echo -e "  ${RED}FAIL${NC} (expected risk>=50, got $RISK/$VERDICT)"
  FAILED=$((FAILED + 1))
fi

# =============================================================================
# Test 3: Password Change (benign)
# =============================================================================

echo -e "${YELLOW}[3/4] Password Change (benign)${NC}"
TASK_ID=$(submit_task '{
  "task_type":"password_change",
  "input":{
    "prompt":"User password change",
    "severity":"low",
    "siem_event":{
      "title":"Password Changed",
      "source_ip":"10.0.0.15",
      "destination_ip":"10.0.0.1",
      "hostname":"DC-01",
      "username":"john.doe",
      "rule_name":"Password_Changed",
      "raw_log":"EventID=4723 User john.doe changed own password successfully"
    }
  }
}')
echo "  Task: $TASK_ID"
BODY=$(poll_task "$TASK_ID")
RISK=$(extract_risk "$BODY"); RISK=${RISK:-100}
VERDICT=$(extract_verdict "$BODY"); VERDICT=${VERDICT:-unknown}
echo "  Risk: $RISK | Verdict: $VERDICT"
if [ "$RISK" -le 35 ] 2>/dev/null && echo "$VERDICT" | grep -qi "benign"; then
  echo -e "  ${GREEN}PASS${NC}"
  PASSED=$((PASSED + 1))
else
  echo -e "  ${RED}FAIL${NC} (expected risk<=35 benign, got $RISK/$VERDICT)"
  FAILED=$((FAILED + 1))
fi

# =============================================================================
# Test 4: Windows Update (benign)
# =============================================================================

echo -e "${YELLOW}[4/4] Windows Update (benign)${NC}"
TASK_ID=$(submit_task '{
  "task_type":"windows_update",
  "input":{
    "prompt":"Scheduled Windows Update",
    "severity":"info",
    "siem_event":{
      "title":"Windows Update Installed",
      "source_ip":"10.0.0.22",
      "destination_ip":"10.0.0.1",
      "hostname":"WS-05",
      "username":"SYSTEM",
      "rule_name":"Windows_Update",
      "raw_log":"Windows Update KB5034441 installed successfully. Reboot pending."
    }
  }
}')
echo "  Task: $TASK_ID"
BODY=$(poll_task "$TASK_ID")
RISK=$(extract_risk "$BODY"); RISK=${RISK:-100}
VERDICT=$(extract_verdict "$BODY"); VERDICT=${VERDICT:-unknown}
echo "  Risk: $RISK | Verdict: $VERDICT"
if [ "$RISK" -le 35 ] 2>/dev/null && echo "$VERDICT" | grep -qi "benign"; then
  echo -e "  ${GREEN}PASS${NC}"
  PASSED=$((PASSED + 1))
else
  echo -e "  ${RED}FAIL${NC} (expected risk<=35 benign, got $RISK/$VERDICT)"
  FAILED=$((FAILED + 1))
fi

# =============================================================================
# Summary
# =============================================================================

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo -e "${CYAN}===========================================${NC}"
echo -e "${CYAN}  RESULTS: $PASSED/$TOTAL passed (${ELAPSED}s)${NC}"
echo -e "${CYAN}===========================================${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
  echo -e "${GREEN}  ALL 4 TESTS PASSED — Quick validation OK${NC}"
  echo ""
  exit 0
else
  echo -e "${RED}  $FAILED TEST(S) FAILED — Validation FAILED${NC}"
  echo ""
  exit 1
fi
