#!/bin/bash
# ZOVARK E2E Test Runner
# Spins up test stack, runs tests, tears down.
#
# Usage: bash tests/e2e/run.sh
#        bash tests/e2e/run.sh --keep  (don't tear down after)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.test.yml"
KEEP_STACK="${1:-}"

echo "========================================="
echo "  ZOVARK End-to-End Test Runner"
echo "========================================="

# Cleanup function
cleanup() {
    if [ "$KEEP_STACK" != "--keep" ]; then
        echo ""
        echo "Tearing down test stack..."
        docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    else
        echo ""
        echo "Stack left running (--keep). Tear down with:"
        echo "  docker compose -f $COMPOSE_FILE down -v"
    fi
}
trap cleanup EXIT

# Step 1: Build and start test stack
echo ""
echo "[1/4] Building test containers..."
docker compose -f "$COMPOSE_FILE" build --quiet

echo ""
echo "[2/4] Starting test stack..."
docker compose -f "$COMPOSE_FILE" up -d

# Step 2: Wait for services
echo ""
echo "[3/4] Waiting for services to be healthy..."

MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    API_HEALTHY=$(curl -sf http://localhost:8091/health 2>/dev/null && echo "yes" || echo "no")
    if [ "$API_HEALTHY" = "yes" ]; then
        echo "  API is healthy after ${ELAPSED}s"
        break
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    echo "  Waiting... (${ELAPSED}s)"
done

if [ "$API_HEALTHY" != "yes" ]; then
    echo "ERROR: API did not become healthy within ${MAX_WAIT}s"
    docker compose -f "$COMPOSE_FILE" logs api
    exit 1
fi

# Give worker a moment to register with Temporal
sleep 5

# Step 3: Run tests
echo ""
echo "[4/4] Running E2E tests..."
export ZOVARK_API_URL="http://localhost:8091"

cd "$PROJECT_ROOT"
python -m pytest tests/e2e/ -v --tb=short --timeout=180 "$@"
TEST_EXIT=$?

echo ""
if [ $TEST_EXIT -eq 0 ]; then
    echo "All E2E tests PASSED."
else
    echo "Some E2E tests FAILED (exit code: $TEST_EXIT)."
fi

exit $TEST_EXIT
