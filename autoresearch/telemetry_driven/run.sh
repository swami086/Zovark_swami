#!/usr/bin/env bash
# Telemetry-Driven AutoResearch — host-side runner.
# Copies scripts into the worker container and executes there.
#
# Usage: bash autoresearch/telemetry_driven/run.sh [--dry-run] [--hours 168] [--max-tests 20]
MSYS_NO_PATHCONV=1
export MSYS_NO_PATHCONV

SCRIPT_DIR="autoresearch/telemetry_driven"
CONTAINER=$(docker compose ps -q worker)
ARGS="${*:---hours 168 --max-tests 20 --wait 120}"

echo "================================================================="
echo "  Telemetry-Driven AutoResearch Engine"
echo "================================================================="
echo "  Args: $ARGS"
echo ""

# Ensure target dir exists
docker exec "$CONTAINER" mkdir -p /app/autoresearch_td/results 2>/dev/null

# Copy Python modules via tar pipe
echo "Syncing modules to worker container..."
(cd "$SCRIPT_DIR" && tar cf - __init__.py collector.py analyzer.py generator.py runner.py delta.py run_cycle.py) | docker exec -i "$CONTAINER" tar xf - -C /app/autoresearch_td/

# Run the cycle with absolute output path
echo ""
docker exec -e PYTHONPATH=/app/autoresearch_td "$CONTAINER" python /app/autoresearch_td/run_cycle.py --output /app/autoresearch_td/results $ARGS
EXIT_CODE=$?

# Copy results back
echo ""
echo "Copying results to host..."
docker cp "$CONTAINER:/app/autoresearch_td/results/." "$SCRIPT_DIR/results/" 2>/dev/null || true

echo "Results in: $SCRIPT_DIR/results/"
exit $EXIT_CODE
