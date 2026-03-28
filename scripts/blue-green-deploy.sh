#!/bin/sh
# ============================================================
# ZOVARK Blue-Green Deployment Script
# Deploys new version alongside current, validates, switches traffic
# Usage: ./scripts/blue-green-deploy.sh <new-version-tag>
#   e.g. ./scripts/blue-green-deploy.sh v1.2.0
# ============================================================
set -eu

VERSION="${1:-}"
if [ -z "${VERSION}" ]; then
    echo "Usage: $0 <version-tag>"
    echo "  e.g. $0 v1.2.0"
    exit 1
fi

NAMESPACE="${ZOVARK_NAMESPACE:-zovark}"
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-/health}"
HEALTH_RETRIES="${HEALTH_RETRIES:-30}"
HEALTH_INTERVAL="${HEALTH_INTERVAL:-5}"
REGISTRY="${ZOVARK_REGISTRY:-ghcr.io/zovark-soc}"

# Colors (only if terminal supports it)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
log_ok() { echo "${GREEN}[OK]${NC} $1"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo "${RED}[ERROR]${NC} $1"; }

# ─── DETERMINE CURRENT COLOR ───────────────────────────
CURRENT_COLOR=$(kubectl get svc zovark-api -n "${NAMESPACE}" -o jsonpath='{.spec.selector.color}' 2>/dev/null || echo "blue")
if [ "${CURRENT_COLOR}" = "blue" ]; then
    NEW_COLOR="green"
else
    NEW_COLOR="blue"
fi

log "Current active: ${CURRENT_COLOR}, deploying: ${NEW_COLOR} (${VERSION})"

# ─── DEPLOY NEW VERSION ────────────────────────────────
log "Deploying ${NEW_COLOR} version (${VERSION})..."

# Update the inactive deployment with new image
for COMPONENT in api worker dashboard; do
    IMAGE="${REGISTRY}/zovark-${COMPONENT}:${VERSION}"
    DEPLOYMENT_NAME="zovark-${COMPONENT}-${NEW_COLOR}"

    log "  Setting ${DEPLOYMENT_NAME} -> ${IMAGE}"

    # Check if the blue-green deployment exists
    if kubectl get deployment "${DEPLOYMENT_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        kubectl set image deployment/"${DEPLOYMENT_NAME}" \
            "${COMPONENT}=${IMAGE}" \
            -n "${NAMESPACE}"
    else
        log_warn "Deployment ${DEPLOYMENT_NAME} not found — creating from active deployment..."
        kubectl get deployment "zovark-${COMPONENT}" -n "${NAMESPACE}" -o yaml | \
            sed "s/zovark-${COMPONENT}/zovark-${COMPONENT}-${NEW_COLOR}/g" | \
            sed "s|image:.*|image: ${IMAGE}|" | \
            sed "s/color: ${CURRENT_COLOR}/color: ${NEW_COLOR}/g" | \
            kubectl apply -f -
    fi
done

# ─── WAIT FOR ROLLOUT ──────────────────────────────────
log "Waiting for ${NEW_COLOR} rollout to complete..."
for COMPONENT in api worker dashboard; do
    DEPLOYMENT_NAME="zovark-${COMPONENT}-${NEW_COLOR}"
    if kubectl get deployment "${DEPLOYMENT_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        kubectl rollout status deployment/"${DEPLOYMENT_NAME}" \
            -n "${NAMESPACE}" --timeout=300s || {
            log_err "${DEPLOYMENT_NAME} rollout failed!"
            exit 1
        }
    fi
done
log_ok "All ${NEW_COLOR} deployments rolled out"

# ─── HEALTH CHECK ──────────────────────────────────────
log "Running health checks on ${NEW_COLOR} API..."

API_POD=$(kubectl get pods -n "${NAMESPACE}" \
    -l "component=api,color=${NEW_COLOR}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "${API_POD}" ]; then
    log_warn "Could not find ${NEW_COLOR} API pod — checking via service..."
    API_POD=$(kubectl get pods -n "${NAMESPACE}" \
        -l "app.kubernetes.io/component=api" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
fi

HEALTHY=false
for i in $(seq 1 "${HEALTH_RETRIES}"); do
    if kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
        wget -q -O /dev/null "http://localhost:8090${HEALTH_ENDPOINT}" 2>/dev/null; then
        HEALTHY=true
        break
    fi
    log "  Health check attempt ${i}/${HEALTH_RETRIES}..."
    sleep "${HEALTH_INTERVAL}"
done

if [ "${HEALTHY}" = "false" ]; then
    log_err "Health check failed after ${HEALTH_RETRIES} attempts!"
    log_err "Rolling back — keeping ${CURRENT_COLOR} as active"
    exit 1
fi

log_ok "Health checks passed on ${NEW_COLOR}"

# ─── SWITCH TRAFFIC ────────────────────────────────────
log "Switching traffic from ${CURRENT_COLOR} to ${NEW_COLOR}..."

# Update the service selector to point to new color
for COMPONENT in api dashboard; do
    kubectl patch svc "zovark-${COMPONENT}" -n "${NAMESPACE}" \
        --type='json' \
        -p="[{\"op\": \"replace\", \"path\": \"/spec/selector/color\", \"value\": \"${NEW_COLOR}\"}]" \
        2>/dev/null || log_warn "Could not patch svc zovark-${COMPONENT} (may not have color selector)"
done

log_ok "Traffic switched to ${NEW_COLOR}"

# ─── KEEP OLD VERSION ──────────────────────────────────
log "Keeping ${CURRENT_COLOR} deployment for rollback capability"
log "  To rollback: ./scripts/rollback.sh"
log "  To cleanup old: kubectl delete deployment zovark-api-${CURRENT_COLOR} zovark-worker-${CURRENT_COLOR} zovark-dashboard-${CURRENT_COLOR} -n ${NAMESPACE}"

# ─── SUMMARY ───────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Blue-Green Deployment Complete"
echo "============================================================"
echo "  Version:     ${VERSION}"
echo "  Active:      ${NEW_COLOR}"
echo "  Standby:     ${CURRENT_COLOR} (available for rollback)"
echo "  Namespace:   ${NAMESPACE}"
echo "============================================================"
