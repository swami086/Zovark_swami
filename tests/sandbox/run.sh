#!/bin/bash
# Run all sandbox security tests.
#
# Usage: bash tests/sandbox/run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "========================================="
echo "  ZOVARK Sandbox Security Tests"
echo "========================================="

cd "$PROJECT_ROOT"

echo ""
echo "[1/4] AST Prefilter Tests..."
python -m pytest tests/sandbox/test_ast_prefilter.py -v --tb=short

echo ""
echo "[2/4] Seccomp Profile Tests..."
python -m pytest tests/sandbox/test_seccomp.py -v --tb=short

echo ""
echo "[3/4] Network Isolation Tests..."
python -m pytest tests/sandbox/test_network_isolation.py -v --tb=short

echo ""
echo "[4/4] Kill Timer & Resource Limit Tests..."
python -m pytest tests/sandbox/test_kill_timer.py tests/sandbox/test_resource_limits.py -v --tb=short

echo ""
echo "========================================="
echo "  All sandbox tests complete"
echo "========================================="
