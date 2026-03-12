#!/bin/bash
# HYDRA Code Coverage Script
#
# Runs pytest with coverage reporting. Designed to run both locally
# and in CI. Fails if coverage drops below 60%.
#
# Usage:
#   bash scripts/coverage.sh                  # Run from project root
#   bash scripts/coverage.sh --html           # Also generate HTML report
#   bash scripts/coverage.sh --threshold 70   # Custom threshold

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
THRESHOLD=60
GENERATE_HTML=false

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --html)
            GENERATE_HTML=true
            shift
            ;;
        --threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo "========================================="
echo "  HYDRA Code Coverage"
echo "  Threshold: ${THRESHOLD}%"
echo "========================================="

cd "$PROJECT_ROOT"

# Build coverage command
COV_CMD="python -m pytest"
COV_CMD="$COV_CMD --cov=worker"
COV_CMD="$COV_CMD --cov=sandbox"
COV_CMD="$COV_CMD --cov-report=term-missing"
COV_CMD="$COV_CMD --cov-fail-under=${THRESHOLD}"

if [ "$GENERATE_HTML" = true ]; then
    COV_CMD="$COV_CMD --cov-report=html:coverage_html"
fi

COV_CMD="$COV_CMD --cov-report=xml:coverage.xml"

# Exclude tests that require full infra
COV_CMD="$COV_CMD tests/sandbox/test_ast_prefilter.py tests/sandbox/test_seccomp.py"
COV_CMD="$COV_CMD -m 'not e2e and not load and not slow'"

echo ""
echo "Running: $COV_CMD"
echo ""

eval $COV_CMD
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "Coverage is above ${THRESHOLD}%."
    if [ "$GENERATE_HTML" = true ]; then
        echo "HTML report: coverage_html/index.html"
    fi
else
    echo ""
    echo "Coverage is below ${THRESHOLD}%. Exit code: $EXIT_CODE"
fi

exit $EXIT_CODE
