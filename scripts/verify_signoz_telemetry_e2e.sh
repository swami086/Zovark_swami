#!/usr/bin/env bash
# End-to-end telemetry verification: emit OTLP from stack + optional SigNoz HTTP + MCP checklist.
#
# Usage (repo root):
#   ./scripts/verify_signoz_telemetry_e2e.sh
#
# With SigNoz JWT (UI → copy access token or API key as Bearer):
#   SIGNOZ_VERIFY=1 SIGNOZ_JWT='eyJ...' ./scripts/verify_signoz_telemetry_e2e.sh
#
# Prerequisites:
#   docker compose --profile tracing up -d
#   Core services: api, worker, zovark-signoz-collector, zovark-signoz, clickhouse
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== 1) SigNoz collector OTLP (host :4318) ==="
if command -v nc >/dev/null 2>&1 && nc -z -w 2 127.0.0.1 4318 2>/dev/null; then
  echo "OK: TCP 127.0.0.1:4318 open (OTLP HTTP)"
else
  echo "WARN: port 4318 not reachable (start: docker compose --profile tracing up -d)"
fi

echo "=== 2) SigNoz UI health (host :3301) ==="
if curl -sf "http://127.0.0.1:3301/api/v1/health" | head -c 120; then
  echo ""
  echo "OK: SigNoz query/frontend reachable"
else
  echo "WARN: SigNoz not on http://127.0.0.1:3301"
fi

echo "=== 3) Worker integration smoke (bind-mount ./worker for current tests) ==="
docker compose run --rm \
  -v "$ROOT/worker:/app" \
  -e ZOVARK_API_URL=http://zovark-api:8090 \
  worker pytest /app/tests/test_signoz_telemetry.py -v --tb=short \
  -k "not SIGNOZ_VERIFY" || {
    echo "FAIL: worker pytest smoke"
    exit 1
  }

if [[ "${SIGNOZ_VERIFY:-}" =~ ^(1|true|yes)$ ]]; then
  echo "=== 4) SigNoz HTTP API (SIGNOZ_VERIFY) ==="
  if [[ -z "${SIGNOZ_JWT:-}" ]]; then
    echo "FAIL: SIGNOZ_JWT required when SIGNOZ_VERIFY=1"
    exit 1
  fi
  docker compose run --rm \
    -v "$ROOT/worker:/app" \
    -e SIGNOZ_VERIFY=1 \
    -e SIGNOZ_JWT="$SIGNOZ_JWT" \
    -e SIGNOZ_BASE="${SIGNOZ_BASE:-http://zovark-signoz:8080}" \
    -e ZOVARK_API_URL=http://zovark-api:8090 \
    worker pytest /app/tests/test_signoz_telemetry.py -v --tb=short \
    -k "SIGNOZ_VERIFY" || {
      echo "FAIL: SigNoz API verification"
      exit 1
    }
else
  echo "=== 4) SigNoz HTTP API: skipped (set SIGNOZ_VERIFY=1 SIGNOZ_JWT=...) ==="
fi

echo ""
echo "=== 5) Cursor SigNoz MCP manual checks (same data as UI) ==="
echo "  - signoz_list_services  timeRange=24h"
echo "  - signoz_search_traces_by_service  service=zovark-api  timeRange=24h"
echo "  - signoz_search_traces_by_service  service=zovark-worker  timeRange=24h"
echo "  - signoz_aggregate_traces  aggregation=count  groupBy=name  service=zovark-api  timeRange=24h"
echo "  - signoz_aggregate_logs    aggregation=count  groupBy=service.name  timeRange=24h"
echo ""
echo "Frontend RUM: load dashboard with VITE_OTEL_ENABLED=true, then re-run signoz_list_services"
echo "  (expect service zovark-dashboard once browser OTLP is enabled)."
echo ""
echo "API structured logs (slog→OTLP): if signoz_aggregate_logs shows only zovark-worker,"
echo "  confirm api container OTEL_ENABLED=true and inspect collector logs for export errors."
echo ""
echo "Done."
