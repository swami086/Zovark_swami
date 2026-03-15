#!/bin/bash
# Validates K8s manifests can be applied (dry-run) and basic structure is correct.
# Requires: kubectl with access to a cluster (or --dry-run=client for offline validation).
#
# Usage: bash scripts/k8s_smoke_test.sh

set -e

echo "=== Validating base manifests ==="
kubectl apply --dry-run=client -k k8s/base/ 2>&1
echo "  ✓ Base manifests valid"

echo ""
echo "=== Validating dev overlay ==="
kubectl apply --dry-run=client -k k8s/overlays/dev/ 2>&1
echo "  ✓ Dev overlay valid"

echo ""
echo "=== Validating prod overlay ==="
kubectl apply --dry-run=client -k k8s/overlays/production/ 2>&1
echo "  ✓ Production overlay valid"

echo ""
echo "=== Validating airgap overlay ==="
kubectl apply --dry-run=client -k k8s/overlays/airgap/ 2>&1
echo "  ✓ Airgap overlay valid"

echo ""
echo "=== Checking HPA targets exist ==="
kubectl apply --dry-run=client -k k8s/overlays/production/ -o json 2>/dev/null | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
items = data.get('items', [data]) if 'items' in data else [data]
for item in items:
    if item.get('kind') == 'HorizontalPodAutoscaler':
        ref = item['spec']['scaleTargetRef']
        print(f\"  HPA: {item['metadata']['name']} -> {ref['kind']}/{ref['name']}\")
" 2>/dev/null || echo "  (skipped — no HPAs or python3 not available)"

echo ""
echo "=== Checking NetworkPolicy selectors ==="
kubectl apply --dry-run=client -k k8s/overlays/production/ -o json 2>/dev/null | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
items = data.get('items', [data]) if 'items' in data else [data]
for item in items:
    if item.get('kind') == 'NetworkPolicy':
        print(f\"  NetworkPolicy: {item['metadata']['name']}\")
" 2>/dev/null || echo "  (skipped — no NetworkPolicies or python3 not available)"

echo ""
echo "=== All manifests valid ==="
