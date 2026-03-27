#!/bin/bash
# ZOVARC Accuracy Gate
#
# Runs accuracy validation tests and fails if accuracy drops below threshold.
# Designed for CI pipelines and local pre-merge checks.
#
# Usage:
#   bash scripts/accuracy-gate.sh                     # Default: 80% threshold, dry-run
#   bash scripts/accuracy-gate.sh --threshold 85      # Custom threshold
#   bash scripts/accuracy-gate.sh --live               # Run against live LLM stack

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
THRESHOLD=80
MODE="--dry-run"
RESULTS_FILE="$PROJECT_ROOT/worker/tests/accuracy/results.json"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        --live)
            MODE=""
            shift
            ;;
        --dry-run)
            MODE="--dry-run"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

echo "========================================="
echo "  ZOVARC Accuracy Gate"
echo "  Threshold: ${THRESHOLD}%"
echo "  Mode: ${MODE:-LIVE}"
echo "========================================="

# Check the validation script exists
VALIDATION_SCRIPT="$PROJECT_ROOT/worker/tests/accuracy/run_validation.py"
if [ ! -f "$VALIDATION_SCRIPT" ]; then
    echo "ERROR: Validation script not found: $VALIDATION_SCRIPT"
    exit 1
fi

# Run validation
echo ""
echo "Running accuracy validation..."
cd "$PROJECT_ROOT/worker"
python tests/accuracy/run_validation.py $MODE

# Parse results
if [ ! -f "$RESULTS_FILE" ]; then
    echo "ERROR: Results file not generated: $RESULTS_FILE"
    exit 1
fi

# Extract metrics and check threshold
echo ""
echo "========================================="
echo "  ACCURACY GATE RESULTS"
echo "========================================="

RESULT=$(python3 -c "
import json, sys

with open('$RESULTS_FILE') as f:
    report = json.load(f)

metrics = report['metrics']
by_cat = report.get('by_category', {})
failures = report.get('failures', [])

accuracy_pct = metrics['accuracy'] * 100
precision_pct = metrics['precision'] * 100
recall_pct = metrics['recall'] * 100
f1_pct = metrics['f1'] * 100
fpr_pct = metrics['fpr'] * 100
confusion = metrics['confusion']

print(f'  Accuracy:   {accuracy_pct:.1f}%')
print(f'  Precision:  {precision_pct:.1f}%')
print(f'  Recall:     {recall_pct:.1f}%')
print(f'  F1 Score:   {f1_pct:.1f}%')
print(f'  FPR:        {fpr_pct:.1f}%')
print(f'  Confusion:  TP={confusion[\"tp\"]} TN={confusion[\"tn\"]} FP={confusion[\"fp\"]} FN={confusion[\"fn\"]}')
print()

# Per-category summary table
if by_cat:
    print('  Category                   Correct/Total  TP  TN  FP  FN')
    print('  ' + '-' * 60)
    for cat, m in sorted(by_cat.items()):
        print(f'  {cat:27s} {m[\"correct\"]:3d}/{m[\"total\"]:3d}       {m[\"tp\"]:2d}  {m[\"tn\"]:2d}  {m[\"fp\"]:2d}  {m[\"fn\"]:2d}')
    print()

# Failures
if failures:
    print(f'  Failures ({len(failures)}):')
    for f in failures[:10]:
        print(f'    {f[\"id\"]:8s} expected={f[\"expected\"]:7s} got={f[\"got\"]:7s}')
    if len(failures) > 10:
        print(f'    ... and {len(failures) - 10} more')
    print()

# Gate decision
threshold = $THRESHOLD
if accuracy_pct >= threshold:
    print(f'  GATE: PASS (accuracy {accuracy_pct:.1f}% >= {threshold}%)')
    sys.exit(0)
else:
    print(f'  GATE: FAIL (accuracy {accuracy_pct:.1f}% < {threshold}%)')
    sys.exit(1)
")

echo "$RESULT"
GATE_EXIT=$?

echo "========================================="

exit $GATE_EXIT
