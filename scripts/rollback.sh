#!/bin/sh
# ============================================================
# ZOVARC Rollback Script
# Switches traffic back to previous (standby) deployment
# Usage: ./scripts/rollback.sh
# ============================================================
set -eu

NAMESPACE="${ZOVARC_NAMESPACE:-zovarc}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
log_ok() { echo "${GREEN}[OK]${NC} $1"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $1"; }

# ─── DETERMINE CURRENT/STANDBY ─────────────────────────
CURRENT_COLOR=$(kubectl get svc zovarc-api -n "${NAMESPACE}" -o jsonpath='{.spec.selector.color}' 2>/dev/null || echo "")

if [ -z "${CURRENT_COLOR}" ]; then
    echo "Could not determine current active color from service selector."
    echo "Ensure blue-green deployment is set up with 'color' label in service selector."
    exit 1
fi

if [ "${CURRENT_COLOR}" = "blue" ]; then
    ROLLBACK_COLOR="green"
else
    ROLLBACK_COLOR="blue"
fi

log "Current active: ${CURRENT_COLOR}"
log "Rolling back to: ${ROLLBACK_COLOR}"

# ─── VERIFY STANDBY EXISTS ─────────────────────────────
STANDBY_READY=true
for COMPONENT in api worker dashboard; do
    DEPLOYMENT_NAME="zovarc-${COMPONENT}-${ROLLBACK_COLOR}"
    if ! kubectl get deployment "${DEPLOYMENT_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        log_warn "Standby deployment ${DEPLOYMENT_NAME} not found"
        STANDBY_READY=false
    fi
done

if [ "${STANDBY_READY}" = "false" ]; then
    echo ""
    echo "${RED}Rollback cannot proceed — standby deployments are missing.${NC}"
    echo "This may mean the previous deployment was cleaned up."
    exit 1
fi

# ─── CONFIRM ───────────────────────────────────────────
printf "Switch traffic from %s to %s? [y/N] " "${CURRENT_COLOR}" "${ROLLBACK_COLOR}"
read -r confirm
case "${confirm}" in
    y|Y|yes|YES) ;;
    *) log "Rollback cancelled."; exit 0 ;;
esac

# ─── SWITCH TRAFFIC ────────────────────────────────────
log "Switching traffic to ${ROLLBACK_COLOR}..."

for COMPONENT in api dashboard; do
    kubectl patch svc "zovarc-${COMPONENT}" -n "${NAMESPACE}" \
        --type='json' \
        -p="[{\"op\": \"replace\", \"path\": \"/spec/selector/color\", \"value\": \"${ROLLBACK_COLOR}\"}]" \
        2>/dev/null || log_warn "Could not patch svc zovarc-${COMPONENT}"
done

log_ok "Traffic rolled back to ${ROLLBACK_COLOR}"

echo ""
echo "============================================================"
echo "  Rollback Complete"
echo "============================================================"
echo "  Active:   ${ROLLBACK_COLOR}"
echo "  Standby:  ${CURRENT_COLOR}"
echo "  Namespace: ${NAMESPACE}"
echo "============================================================"
