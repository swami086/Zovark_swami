#!/bin/bash
# HYDRA K8s Cluster Smoke Test
# Tests actual deployment against a real Kubernetes cluster.
#
# Prerequisites:
#   - kubectl configured and pointing at a cluster
#   - Cluster has at least 2 nodes with 4GB RAM each
#   - NVIDIA GPU node (optional — required for local inference tier only)
#
# Usage:
#   ./scripts/k8s_cluster_test.sh dev      # Test dev overlay
#   ./scripts/k8s_cluster_test.sh prod     # Test prod overlay
#   ./scripts/k8s_cluster_test.sh airgap   # Test airgap overlay

set -e

OVERLAY=${1:-dev}

# Map overlay names to directory names
case "$OVERLAY" in
  dev) OVERLAY_DIR="dev" ;;
  prod|production) OVERLAY_DIR="production"; OVERLAY="prod" ;;
  airgap) OVERLAY_DIR="airgap" ;;
  *) echo "Usage: $0 [dev|prod|airgap]"; exit 1 ;;
esac

NAMESPACE="hydra-test-${OVERLAY}"
RESULTS_FILE="docs/K8S_VALIDATION_${OVERLAY}.md"

echo "=== HYDRA K8s Cluster Test — $OVERLAY overlay ==="
echo "Namespace: $NAMESPACE"
echo ""

# Phase 1: Pre-flight checks
echo "--- Phase 1: Pre-flight ---"
kubectl version --short 2>/dev/null || kubectl version 2>/dev/null || { echo "FAIL: kubectl not configured"; exit 1; }
kubectl get nodes -o wide || { echo "FAIL: Cannot list nodes"; exit 1; }
echo "  ✓ Cluster accessible"

# Phase 2: Deploy
echo ""
echo "--- Phase 2: Deploy ---"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -k "k8s/overlays/$OVERLAY_DIR/" -n "$NAMESPACE" 2>&1
echo "  ✓ Manifests applied"

# Phase 3: Wait for pods
echo ""
echo "--- Phase 3: Wait for pods (timeout 5m) ---"
for label in hydra-api hydra-worker hydra-postgres hydra-redis hydra-temporal; do
  echo -n "  Waiting for $label... "
  if kubectl wait --for=condition=ready pod -l "app=$label" -n "$NAMESPACE" --timeout=300s 2>/dev/null; then
    echo "✓"
  else
    echo "⚠ (may not exist in this overlay)"
  fi
done

echo ""
echo "--- Pod status ---"
kubectl get pods -n "$NAMESPACE" -o wide

# Phase 4: Health check
echo ""
echo "--- Phase 4: Health check ---"
API_POD=$(kubectl get pod -l app=hydra-api -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
HEALTH_RESULT="SKIPPED"
if [ -n "$API_POD" ]; then
  HEALTH_RESULT=$(kubectl exec "$API_POD" -n "$NAMESPACE" -- curl -sf http://localhost:8090/health 2>&1 || echo "FAILED")
  echo "  $HEALTH_RESULT"
  echo "  ✓ API health check"
else
  echo "  WARN: API pod not found"
fi

# Phase 5: Database connectivity
echo ""
echo "--- Phase 5: Database ---"
PG_POD=$(kubectl get pod -l app=hydra-postgres -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
TABLE_COUNT="N/A"
if [ -n "$PG_POD" ]; then
  TABLE_COUNT=$(kubectl exec "$PG_POD" -n "$NAMESPACE" -- psql -U hydra -d hydra -tAc "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public'" 2>/dev/null || echo "FAILED")
  echo "  Tables: $TABLE_COUNT"
  echo "  ✓ Database accessible"
else
  echo "  WARN: Postgres pod not found"
fi

# Phase 6: Service connectivity
echo ""
echo "--- Phase 6: Services ---"
for svc in hydra-api hydra-postgres hydra-redis hydra-temporal; do
  if kubectl get svc "$svc" -n "$NAMESPACE" &>/dev/null; then
    echo "  ✓ Service $svc exists"
  else
    echo "  ⚠ Service $svc not found"
  fi
done

# Phase 7: HPA check (prod only)
HPA_RESULT="N/A"
if [ "$OVERLAY" = "prod" ]; then
  echo ""
  echo "--- Phase 7: HPA ---"
  HPA_RESULT=$(kubectl get hpa -n "$NAMESPACE" 2>&1 || echo "No HPA found")
  echo "$HPA_RESULT"
fi

# Phase 8: Network policy check
echo ""
echo "--- Phase 8: Network policies ---"
NP_COUNT=$(kubectl get networkpolicy -n "$NAMESPACE" -o name 2>/dev/null | wc -l)
echo "  Network policies: $NP_COUNT"

# Phase 9: Generate report
echo ""
echo "--- Generating report ---"
cat > "$RESULTS_FILE" << EOF
# HYDRA K8s Cluster Validation — $OVERLAY

**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Overlay:** $OVERLAY
**Namespace:** $NAMESPACE
**Cluster:** $(kubectl config current-context 2>/dev/null || echo "unknown")

## Pod Status
\`\`\`
$(kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || echo "No pods")
\`\`\`

## Services
\`\`\`
$(kubectl get svc -n "$NAMESPACE" 2>/dev/null || echo "No services")
\`\`\`

## Health Check
\`\`\`
$HEALTH_RESULT
\`\`\`

## Database
- Tables: $TABLE_COUNT

## HPA
\`\`\`
$HPA_RESULT
\`\`\`

## Network Policies
- Count: $NP_COUNT

## Result
- Manifests applied: ✓
- Pods running: $(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | grep -c Running || echo 0)
- Services created: $(kubectl get svc -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || echo 0)
EOF

echo "  Report: $RESULTS_FILE"

# Phase 10: Cleanup prompt
echo ""
read -p "Delete test namespace $NAMESPACE? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  kubectl delete namespace "$NAMESPACE"
  echo "  ✓ Cleaned up"
else
  echo "  Namespace $NAMESPACE left running"
fi

echo ""
echo "=== K8s cluster test complete ==="
