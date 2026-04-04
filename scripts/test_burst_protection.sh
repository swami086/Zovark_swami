#!/usr/bin/env bash
# ============================================================
# Zovark v3.2 — Burst Protection Integration Test
#
# Tests all 3 layers of pre-Temporal burst protection:
#   Layer 1: Redis exact dedup (identical alerts)
#   Layer 2: Batch buffer (same source/dest IP grouping)
#   Layer 3: SIEM ingest rate limit exemption
#
# Requirements:
#   - Running Zovark stack at localhost:8090
#   - Admin credentials (admin@test.local / TestPass2026)
#   - jq (optional — falls back to grep-based parsing)
#
# Usage:
#   ./scripts/test_burst_protection.sh
#
# Exit codes:
#   0 — all tests passed
#   1 — one or more tests failed
# ============================================================
set -euo pipefail
export MSYS_NO_PATHCONV=1

API="http://localhost:8090"
PASS_COUNT=0
FAIL_COUNT=0

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- JSON helper (jq with grep fallback) ---
HAS_JQ=false
if command -v jq &>/dev/null; then
    HAS_JQ=true
fi

json_field() {
    local json="$1"
    local field="$2"
    if $HAS_JQ; then
        echo "$json" | jq -r ".$field // empty" 2>/dev/null
    else
        echo "$json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/"
    fi
}

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL_COUNT++)) || true; }
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# --- Unique run ID to avoid cross-run interference ---
RUN_ID="bp$(date +%s)"

echo ""
echo "============================================="
echo "  Zovark Burst Protection Integration Test"
echo "  Run ID: $RUN_ID"
echo "============================================="
echo ""

# --- Preflight: check API health ---
log_info "Checking API health..."
HEALTH=$(curl -sf --max-time 5 "$API/health" 2>/dev/null || echo "")
if [ -z "$HEALTH" ]; then
    echo -e "${RED}ERROR: API not reachable at $API${NC}"
    echo "Start the stack first: docker compose up -d"
    exit 1
fi
log_info "API is healthy"

# --- Login ---
log_info "Authenticating..."
LOGIN_RESP=$(curl -sf -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@test.local","password":"TestPass2026"}' 2>/dev/null || echo "")

TOKEN=$(json_field "$LOGIN_RESP" "token")

if [ -z "$TOKEN" ] || [ ${#TOKEN} -lt 50 ]; then
    echo -e "${RED}ERROR: Failed to authenticate (token length: ${#TOKEN:-0})${NC}"
    exit 1
fi
log_info "Authenticated (token: ${TOKEN:0:16}...)"

AUTH="-H Authorization:\ Bearer\ $TOKEN"

# Helper: submit a task via /api/v1/tasks, return the HTTP response body
submit_task() {
    local payload="$1"
    curl -s -w "\n%{http_code}" -X POST "$API/api/v1/tasks" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$payload" 2>/dev/null
}

# Helper: submit via /api/v1/ingest/splunk, return HTTP response body + status code
submit_splunk() {
    local payload="$1"
    curl -s -w "\n%{http_code}" -X POST "$API/api/v1/ingest/splunk" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$payload" 2>/dev/null
}

# ============================================================
# TEST 1: Identical Alert Dedup (20 alerts)
#
# Submit 20 identical brute_force alerts. The first creates a
# workflow; the remaining 19 should be deduplicated (Redis exact
# hash match). Expect <=2 workflows created.
# ============================================================
echo ""
echo "---------------------------------------------"
echo "  TEST 1: Identical Alert Dedup (20 alerts)"
echo "---------------------------------------------"

T1_IP="192.168.${RUN_ID:2:1}.101"
T1_HOSTNAME="test1-${RUN_ID}"
T1_WORKFLOWS=0
T1_DEDUPED=0
T1_BATCHED=0

for i in $(seq 1 20); do
    RESP=$(submit_task "{
        \"task_type\": \"brute_force\",
        \"input\": {
            \"prompt\": \"SSH brute force\",
            \"severity\": \"high\",
            \"source_ip\": \"$T1_IP\",
            \"siem_event\": {
                \"title\": \"SSH Brute Force\",
                \"source_ip\": \"$T1_IP\",
                \"username\": \"root\",
                \"hostname\": \"$T1_HOSTNAME\",
                \"rule_name\": \"BruteForce-${RUN_ID}\",
                \"raw_log\": \"500 failed password attempts for root from $T1_IP port 22\"
            }
        }
    }")

    HTTP_CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | sed '$d')
    STATUS=$(json_field "$BODY" "status")

    if [ "$STATUS" = "deduplicated" ]; then
        ((T1_DEDUPED++)) || true
    elif [ "$STATUS" = "batched" ]; then
        ((T1_BATCHED++)) || true
    else
        ((T1_WORKFLOWS++)) || true
    fi
done

T1_NON_WORKFLOW=$((T1_DEDUPED + T1_BATCHED))
log_info "Test 1 results: workflows=$T1_WORKFLOWS, deduped=$T1_DEDUPED, batched=$T1_BATCHED"

if [ "$T1_WORKFLOWS" -le 2 ]; then
    log_pass "Identical alert dedup: $T1_WORKFLOWS workflows created (expected <=2), $T1_NON_WORKFLOW suppressed"
else
    log_fail "Identical alert dedup: $T1_WORKFLOWS workflows created (expected <=2), $T1_NON_WORKFLOW suppressed"
fi

# Wait for batch window to expire before next test
log_info "Waiting 8s for batch window to expire..."
sleep 8

# ============================================================
# TEST 2: Same Source IP Batch (10 alerts)
#
# Submit 10 brute_force alerts with the same source_ip but
# different raw_logs (so they are NOT exact duplicates).
# The batch buffer should group them. Expect <=3 workflows.
# ============================================================
echo ""
echo "---------------------------------------------"
echo "  TEST 2: Same Source IP Batch (10 alerts)"
echo "---------------------------------------------"

T2_IP="10.20.${RUN_ID:2:1}.201"
T2_WORKFLOWS=0
T2_DEDUPED=0
T2_BATCHED=0

for i in $(seq 1 10); do
    RESP=$(submit_task "{
        \"task_type\": \"brute_force\",
        \"input\": {
            \"prompt\": \"SSH brute force variant $i\",
            \"severity\": \"high\",
            \"source_ip\": \"$T2_IP\",
            \"siem_event\": {
                \"title\": \"SSH Brute Force ${RUN_ID}-t2-$i\",
                \"source_ip\": \"$T2_IP\",
                \"username\": \"user${i}\",
                \"hostname\": \"host-t2-${RUN_ID}-$i\",
                \"rule_name\": \"BruteForce-${RUN_ID}-t2-$i\",
                \"raw_log\": \"$i failed password attempts for user${i} from $T2_IP port $((22000+i)) on host-t2-$i at $(date +%s)${i}\"
            }
        }
    }")

    HTTP_CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | sed '$d')
    STATUS=$(json_field "$BODY" "status")

    if [ "$STATUS" = "deduplicated" ]; then
        ((T2_DEDUPED++)) || true
    elif [ "$STATUS" = "batched" ]; then
        ((T2_BATCHED++)) || true
    else
        ((T2_WORKFLOWS++)) || true
    fi
done

log_info "Test 2 results: workflows=$T2_WORKFLOWS, deduped=$T2_DEDUPED, batched=$T2_BATCHED"

if [ "$T2_WORKFLOWS" -le 3 ]; then
    log_pass "Same source IP batch: $T2_WORKFLOWS workflows created (expected <=3), $T2_BATCHED batched"
else
    log_fail "Same source IP batch: $T2_WORKFLOWS workflows created (expected <=3), $T2_BATCHED batched"
fi

# Wait for batch window to expire
log_info "Waiting 8s for batch window to expire..."
sleep 8

# ============================================================
# TEST 3: Same Destination IP Batch (10 alerts)
#
# Submit 10 brute_force alerts from DIFFERENT source_ips but
# with the SAME destination_ip. Tests the dual batch key fix
# (Layer 2 checks both src and dst keys). Expect <=3 workflows.
# ============================================================
echo ""
echo "---------------------------------------------"
echo "  TEST 3: Same Dest IP Batch (10 alerts)"
echo "---------------------------------------------"

T3_DST_IP="172.16.${RUN_ID:2:1}.100"
T3_WORKFLOWS=0
T3_DEDUPED=0
T3_BATCHED=0

for i in $(seq 1 10); do
    T3_SRC="10.30.$((i + 100)).${RUN_ID:2:1}"
    RESP=$(submit_task "{
        \"task_type\": \"brute_force\",
        \"input\": {
            \"prompt\": \"Inbound brute force from $T3_SRC\",
            \"severity\": \"high\",
            \"source_ip\": \"$T3_SRC\",
            \"dest_ip\": \"$T3_DST_IP\",
            \"siem_event\": {
                \"title\": \"Inbound BF ${RUN_ID}-t3-$i\",
                \"source_ip\": \"$T3_SRC\",
                \"destination_ip\": \"$T3_DST_IP\",
                \"username\": \"admin\",
                \"hostname\": \"firewall-t3-${RUN_ID}\",
                \"rule_name\": \"InboundBF-${RUN_ID}-t3-$i\",
                \"raw_log\": \"Blocked inbound brute force from $T3_SRC to $T3_DST_IP on port 22 attempt $i uid=$(date +%s)${i}\"
            }
        }
    }")

    HTTP_CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | sed '$d')
    STATUS=$(json_field "$BODY" "status")

    if [ "$STATUS" = "deduplicated" ]; then
        ((T3_DEDUPED++)) || true
    elif [ "$STATUS" = "batched" ]; then
        ((T3_BATCHED++)) || true
    else
        ((T3_WORKFLOWS++)) || true
    fi
done

log_info "Test 3 results: workflows=$T3_WORKFLOWS, deduped=$T3_DEDUPED, batched=$T3_BATCHED"

if [ "$T3_WORKFLOWS" -le 3 ]; then
    log_pass "Same dest IP batch: $T3_WORKFLOWS workflows created (expected <=3), $T3_BATCHED batched"
else
    log_fail "Same dest IP batch: $T3_WORKFLOWS workflows created (expected <=3), $T3_BATCHED batched"
fi

# ============================================================
# TEST 4: Critical TTL Dedup Persistence
#
# Critical alerts have a 900s (15 min) dedup TTL. Submit a
# critical alert, wait 120s, resubmit the identical alert.
# The second should still be deduplicated (well within TTL).
# ============================================================
echo ""
echo "---------------------------------------------"
echo "  TEST 4: Critical TTL Test (120s wait)"
echo "---------------------------------------------"

T4_IP="10.40.${RUN_ID:2:1}.1"
T4_RAW="EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc from $T4_IP"
T4_PAYLOAD="{
    \"task_type\": \"kerberoasting\",
    \"input\": {
        \"prompt\": \"Kerberoasting ${RUN_ID}\",
        \"severity\": \"critical\",
        \"source_ip\": \"$T4_IP\",
        \"siem_event\": {
            \"title\": \"Kerberoasting ${RUN_ID}\",
            \"source_ip\": \"$T4_IP\",
            \"username\": \"svc_backup\",
            \"hostname\": \"dc01-t4-${RUN_ID}\",
            \"rule_name\": \"Kerberoast-${RUN_ID}\",
            \"raw_log\": \"$T4_RAW\"
        }
    }
}"

log_info "Submitting first critical alert..."
RESP1=$(submit_task "$T4_PAYLOAD")
BODY1=$(echo "$RESP1" | sed '$d')
STATUS1=$(json_field "$BODY1" "status")
log_info "First submit status: $STATUS1"

log_info "Waiting 120 seconds (testing TTL persistence)..."
sleep 120

log_info "Resubmitting identical critical alert..."
RESP2=$(submit_task "$T4_PAYLOAD")
BODY2=$(echo "$RESP2" | sed '$d')
STATUS2=$(json_field "$BODY2" "status")
log_info "Second submit status: $STATUS2"

if [ "$STATUS2" = "deduplicated" ]; then
    log_pass "Critical TTL dedup: second alert deduplicated after 120s (TTL=900s)"
else
    log_fail "Critical TTL dedup: second alert status='$STATUS2' (expected 'deduplicated'). TTL may have expired prematurely."
fi

# Wait for batch window to expire
log_info "Waiting 8s for batch window to expire..."
sleep 8

# ============================================================
# TEST 5: SIEM Route Not Rate Limited (150 alerts)
#
# Submit 150 alerts via /api/v1/ingest/splunk in under 60s.
# The SIEM ingest route is exempt from the per-tenant rate
# limiter. Expect 0 HTTP 429 responses.
#
# Each alert uses a unique source_ip + rule_name to avoid
# dedup and batch absorption.
# ============================================================
echo ""
echo "---------------------------------------------"
echo "  TEST 5: SIEM Route Not Rate Limited (150)"
echo "---------------------------------------------"

T5_429_COUNT=0
T5_OK_COUNT=0
T5_ERR_COUNT=0
T5_START=$(date +%s)

for i in $(seq 1 150); do
    # Generate unique IP: 10.X.Y.1 where X and Y vary
    T5_OCT2=$(( (i / 254) + 1 ))
    T5_OCT3=$(( (i % 254) + 1 ))
    T5_SRC_IP="10.${T5_OCT2}.${T5_OCT3}.1"

    RESP=$(submit_splunk "{
        \"event\": {
            \"signature\": \"brute_force_siem_test_${RUN_ID}_${i}\",
            \"src_ip\": \"$T5_SRC_IP\",
            \"severity\": \"medium\",
            \"raw\": \"Failed password for user_${i} from $T5_SRC_IP port $((40000+i)) ssh2 uid=${RUN_ID}${i}\"
        }
    }")

    HTTP_CODE=$(echo "$RESP" | tail -1)

    if [ "$HTTP_CODE" = "429" ]; then
        ((T5_429_COUNT++)) || true
    elif [ "$HTTP_CODE" = "200" ]; then
        ((T5_OK_COUNT++)) || true
    else
        ((T5_ERR_COUNT++)) || true
    fi
done

T5_END=$(date +%s)
T5_DURATION=$(( T5_END - T5_START ))

log_info "Test 5 results: 200=$T5_OK_COUNT, 429=$T5_429_COUNT, other_errors=$T5_ERR_COUNT (${T5_DURATION}s elapsed)"

if [ "$T5_429_COUNT" -eq 0 ]; then
    log_pass "SIEM rate limit exempt: 0 HTTP 429 from 150 alerts in ${T5_DURATION}s"
else
    log_fail "SIEM rate limit exempt: $T5_429_COUNT HTTP 429 responses (expected 0)"
fi

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================="
echo "  Burst Protection Test Summary"
echo "============================================="
echo -e "  ${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "  ${RED}Failed: $FAIL_COUNT${NC}"
echo "============================================="
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}RESULT: $FAIL_COUNT test(s) failed${NC}"
    exit 1
else
    echo -e "${GREEN}RESULT: All $PASS_COUNT tests passed${NC}"
    exit 0
fi
