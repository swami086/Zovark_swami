#!/bin/bash
# ZOVARK Load Test Runner
#
# Runs Locust load tests with configurable profiles and threshold checks.
#
# Usage:
#   bash tests/load/run.sh                    # Run baseline profile
#   bash tests/load/run.sh smoke              # Run smoke test
#   bash tests/load/run.sh stress             # Run stress test
#   bash tests/load/run.sh baseline --host http://localhost:8090

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.json"
PROFILE="${1:-baseline}"
HOST="${3:-http://localhost:8090}"

# Override host if --host flag is provided
if [[ "${2:-}" == "--host" ]] && [[ -n "${3:-}" ]]; then
    HOST="$3"
fi

echo "========================================="
echo "  ZOVARK Load Test"
echo "  Profile: $PROFILE"
echo "  Host: $HOST"
echo "========================================="

# Check locust is installed
if ! command -v locust &>/dev/null; then
    echo "ERROR: locust not found. Install with: pip install locust"
    exit 1
fi

# Read config
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE"
    exit 1
fi

# Parse profile config using Python (portable JSON parsing)
read -r USERS SPAWN_RATE DURATION <<< $(python3 -c "
import json, sys
with open('$CONFIG_FILE') as f:
    cfg = json.load(f)
p = cfg['profiles'].get('$PROFILE')
if not p:
    print(f'Profile $PROFILE not found. Available: {list(cfg[\"profiles\"].keys())}', file=sys.stderr)
    sys.exit(1)
print(f\"{p['users']} {p['spawn_rate']} {p['duration']}\")
")

echo ""
echo "Configuration:"
echo "  Users:      $USERS"
echo "  Spawn Rate: $SPAWN_RATE/s"
echo "  Duration:   $DURATION"
echo ""

# Run locust in headless mode
RESULTS_DIR="$PROJECT_ROOT/tests/results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
STATS_FILE="$RESULTS_DIR/load_test_${PROFILE}_${TIMESTAMP}"

echo "Running load test..."
locust \
    -f "$SCRIPT_DIR/locustfile.py" \
    --headless \
    -u "$USERS" \
    -r "$SPAWN_RATE" \
    -t "$DURATION" \
    --host "$HOST" \
    --csv "$STATS_FILE" \
    --html "$STATS_FILE.html" \
    2>&1 | tee "$STATS_FILE.log"

LOCUST_EXIT=$?

echo ""
echo "========================================="
echo "  Load Test Complete"
echo "========================================="
echo "  CSV stats: ${STATS_FILE}_stats.csv"
echo "  HTML report: ${STATS_FILE}.html"
echo "  Log: ${STATS_FILE}.log"

exit $LOCUST_EXIT
