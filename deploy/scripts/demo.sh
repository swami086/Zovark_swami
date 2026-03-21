#!/bin/bash
# ============================================================
# HYDRA Demo Mode
# Starts services and generates alerts at a steady pace
# ============================================================
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_DIR="$(dirname "$DEPLOY_DIR")"

cd "$DEPLOY_DIR"

echo "=== HYDRA Demo Mode ==="
echo ""

# Start services if not running
RUNNING=$(docker compose -f docker-compose.production.yml ps --status running -q 2>/dev/null | wc -l)
if [ "$RUNNING" -lt 5 ]; then
    echo "Starting services..."
    docker compose -f docker-compose.production.yml up -d
    echo "Waiting for services..."
    sleep 15
fi

# Health check
"$(dirname "$0")/health-check.sh" || true

echo ""
echo "Demo mode active."
echo "  Dashboard: http://localhost:${DASHBOARD_PORT:-3000}"
echo "  API:       http://localhost:${API_PORT:-8090}"
echo ""
echo "Starting alert generator (1 alert every 30 seconds)..."
echo "Press Ctrl+C to stop."
echo ""

# Run alert generator
python3 "$PROJECT_DIR/scripts/alert_generator.py" \
    --rate 2 \
    --api-url "http://localhost:${API_PORT:-8090}" \
    --severity-dist "critical:10,high:30,medium:40,low:20"
