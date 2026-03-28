#!/bin/bash
# ============================================================
# ZOVARK Temporal Cleanup — terminate stale V1 workflows
# Usage: bash scripts/cleanup_temporal.sh
# ============================================================
set -euo pipefail

TEMPORAL_HOST="${TEMPORAL_ADDRESS:-temporal:7233}"
NAMESPACE="default"
TERMINATED=0

echo "=== ZOVARK Temporal Cleanup ==="
echo "Temporal: $TEMPORAL_HOST"
echo ""

# List all open workflows
echo "Open workflows:"
docker compose exec temporal tctl --ns "$NAMESPACE" workflow list --status open --print_raw_time 2>/dev/null | head -30 || {
    echo "  (Could not reach Temporal — is it running?)"
    exit 1
}

echo ""
echo "Terminating legacy ExecuteTaskWorkflow instances..."

# Get workflow IDs of legacy ExecuteTaskWorkflow
LEGACY_IDS=$(docker compose exec temporal tctl --ns "$NAMESPACE" workflow list --status open --print_raw_time 2>/dev/null \
  | grep "ExecuteTaskWorkflow" \
  | awk '{print $1}' || true)

if [ -z "$LEGACY_IDS" ]; then
    echo "  No legacy ExecuteTaskWorkflow workflows found."
else
    while IFS= read -r WID; do
        if [ -n "$WID" ]; then
            echo "  Terminating: $WID"
            docker compose exec temporal tctl --ns "$NAMESPACE" workflow terminate --workflow_id "$WID" --reason "Legacy V1 cleanup" 2>/dev/null || true
            TERMINATED=$((TERMINATED + 1))
        fi
    done <<< "$LEGACY_IDS"
fi

echo ""
echo "=== Results ==="
echo "Terminated: $TERMINATED legacy workflow(s)"

# Verify remaining
echo ""
echo "Remaining open workflows:"
docker compose exec temporal tctl --ns "$NAMESPACE" workflow list --status open --print_raw_time 2>/dev/null | head -20 || echo "  (none)"

# Check for V2 workflows
V2_COUNT=$(docker compose exec temporal tctl --ns "$NAMESPACE" workflow list --status open --print_raw_time 2>/dev/null \
  | grep -c "InvestigationWorkflowV2" || true)
echo ""
echo "Active InvestigationWorkflowV2 workflows: $V2_COUNT"
echo ""
echo "Cleanup complete."
