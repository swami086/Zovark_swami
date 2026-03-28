#!/bin/sh
# ============================================================
# ZOVARK Disaster Recovery Failover Script
# Automates failover from primary to secondary region
# Usage: ./scripts/dr-failover.sh <target-region>
#   e.g. ./scripts/dr-failover.sh eu-west-1
# ============================================================
set -eu

TARGET_REGION="${1:-}"
if [ -z "${TARGET_REGION}" ]; then
    echo "Usage: $0 <target-region>"
    echo "  e.g. $0 eu-west-1"
    echo ""
    echo "Available regions:"
    echo "  us-east-1    (primary)"
    echo "  eu-west-1    (secondary)"
    echo "  ap-southeast-1 (secondary)"
    exit 1
fi

NAMESPACE="${ZOVARK_NAMESPACE:-zovark}"
PRIMARY_DB_HOST="${PRIMARY_DB_HOST:-postgres-primary.us-east-1}"
LOG_FILE="/tmp/zovark-dr-failover-$(date +%Y%m%d_%H%M%S).log"

log() {
    MSG="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "${MSG}"
    echo "${MSG}" >> "${LOG_FILE}"
}

log "============================================================"
log "ZOVARK DR Failover — Target Region: ${TARGET_REGION}"
log "============================================================"
log "Log file: ${LOG_FILE}"
echo ""

# ─── PRE-FLIGHT CHECKS ─────────────────────────────────
log "Running pre-flight checks..."

# Check kubectl connectivity to target region
if ! kubectl config use-context "zovark-${TARGET_REGION}" 2>/dev/null; then
    log "WARNING: Could not switch to context zovark-${TARGET_REGION}"
    log "Attempting with current context..."
fi

# Verify target region has deployments
if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
    log "ERROR: Namespace ${NAMESPACE} not found in target region"
    exit 1
fi

log "Pre-flight checks passed"

# ─── STEP 1: PROMOTE DATABASE REPLICA ──────────────────
log "Step 1: Promoting PostgreSQL replica in ${TARGET_REGION}..."

# Find the postgres pod in the target region
PG_POD=$(kubectl get pods -n "${NAMESPACE}" -l component=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "${PG_POD}" ]; then
    log "  Found PostgreSQL pod: ${PG_POD}"

    # Check if this is already a primary
    IS_REPLICA=$(kubectl exec -n "${NAMESPACE}" "${PG_POD}" -- \
        psql -U zovark -d zovark -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d ' ' || echo "unknown")

    if [ "${IS_REPLICA}" = "t" ]; then
        log "  Promoting replica to primary..."
        kubectl exec -n "${NAMESPACE}" "${PG_POD}" -- \
            pg_ctl promote -D /var/lib/postgresql/data 2>/dev/null || \
            log "  WARNING: pg_ctl promote failed (may need manual intervention)"

        # Wait for promotion
        sleep 5

        IS_PRIMARY=$(kubectl exec -n "${NAMESPACE}" "${PG_POD}" -- \
            psql -U zovark -d zovark -t -c "SELECT NOT pg_is_in_recovery();" 2>/dev/null | tr -d ' ' || echo "unknown")

        if [ "${IS_PRIMARY}" = "t" ]; then
            log "  PostgreSQL promoted to primary successfully"
        else
            log "  WARNING: PostgreSQL promotion status uncertain — verify manually"
        fi
    elif [ "${IS_REPLICA}" = "f" ]; then
        log "  PostgreSQL is already a primary — skipping promotion"
    else
        log "  WARNING: Could not determine PostgreSQL role"
    fi
else
    log "  WARNING: No PostgreSQL pod found — skipping DB promotion"
fi

# ─── STEP 2: UPDATE APPLICATION CONFIG ─────────────────
log "Step 2: Updating application configuration..."

# Update the database URL to point to local (promoted) PostgreSQL
kubectl patch secret zovark-db-credentials -n "${NAMESPACE}" \
    --type='json' \
    -p="[{\"op\": \"replace\", \"path\": \"/stringData/direct-url\", \"value\": \"postgresql://zovark:zovark_dev_2026@postgres:5432/zovark\"}]" \
    2>/dev/null || log "  WARNING: Could not update DB credentials secret"

log "  Application config updated"

# ─── STEP 3: RESTART SERVICES ──────────────────────────
log "Step 3: Restarting application services..."

for COMPONENT in api worker; do
    if kubectl get deployment "zovark-${COMPONENT}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        kubectl rollout restart deployment/"zovark-${COMPONENT}" -n "${NAMESPACE}"
        log "  Restarted zovark-${COMPONENT}"
    fi
done

# Wait for rollouts
for COMPONENT in api worker; do
    if kubectl get deployment "zovark-${COMPONENT}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        kubectl rollout status deployment/"zovark-${COMPONENT}" -n "${NAMESPACE}" --timeout=180s 2>/dev/null || \
            log "  WARNING: zovark-${COMPONENT} rollout timeout"
    fi
done

log "  Services restarted"

# ─── STEP 4: HEALTH CHECK ──────────────────────────────
log "Step 4: Running health checks..."

HEALTHY=false
for i in $(seq 1 20); do
    API_POD=$(kubectl get pods -n "${NAMESPACE}" -l component=api --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "${API_POD}" ]; then
        if kubectl exec -n "${NAMESPACE}" "${API_POD}" -- wget -q -O /dev/null http://localhost:8090/health 2>/dev/null; then
            HEALTHY=true
            break
        fi
    fi
    log "  Health check attempt ${i}/20..."
    sleep 5
done

if [ "${HEALTHY}" = "true" ]; then
    log "  Health checks PASSED"
else
    log "  WARNING: Health checks FAILED — manual verification required"
fi

# ─── STEP 5: DNS UPDATE REMINDER ───────────────────────
log "Step 5: DNS update required"
echo ""
echo "============================================================"
echo "  MANUAL STEP REQUIRED: Update DNS"
echo "============================================================"
echo ""
echo "  Update DNS records to point to ${TARGET_REGION}:"
echo ""
echo "  Option A (Route 53):"
echo "    aws route53 change-resource-record-sets \\"
echo "      --hosted-zone-id <ZONE_ID> \\"
echo "      --change-batch '{\"Changes\":[{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"zovark.example.com\",\"Type\":\"A\",\"SetIdentifier\":\"${TARGET_REGION}\",\"Region\":\"${TARGET_REGION}\",\"AliasTarget\":{\"DNSName\":\"<ALB_DNS>\",\"HostedZoneId\":\"<ALB_ZONE>\",\"EvaluateTargetHealth\":true}}}]}'"
echo ""
echo "  Option B (Manual):"
echo "    Update zovark.example.com A record to ${TARGET_REGION} load balancer IP"
echo ""
echo "============================================================"

# ─── SUMMARY ───────────────────────────────────────────
log ""
log "============================================================"
log "  DR Failover Summary"
log "============================================================"
log "  Target Region:  ${TARGET_REGION}"
log "  DB Promotion:   $([ -n "${PG_POD}" ] && echo "Attempted" || echo "Skipped")"
log "  Services:       Restarted"
log "  Health Check:   $([ "${HEALTHY}" = "true" ] && echo "PASSED" || echo "NEEDS ATTENTION")"
log "  DNS:            MANUAL UPDATE REQUIRED"
log "  Log File:       ${LOG_FILE}"
log "============================================================"
