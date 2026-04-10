#!/usr/bin/env bash
# Emit API + worker OpenTelemetry traffic for SigNoz validation.
# Usage (from repo root, tracing profile up):
#   ./scripts/signoz_smoke_emit.sh
# Or run pytest suite:
#   docker compose run --rm worker pytest tests/test_signoz_telemetry.py -v

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${ZOVARK_API_URL:-http://localhost:8090}"
RUN_ID="$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')"

echo "[signoz-smoke] API=$API run_id=$RUN_ID"

curl -sS -o /dev/null -w "login_fail HTTP %{http_code}\n" -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@test.local\",\"password\":\"bad-$RUN_ID\"}" || true

TOKEN="$(curl -sS -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)"

if [[ -n "${TOKEN}" ]]; then
  curl -sS -o /dev/null -w "tasks HTTP %{http_code}\n" "$API/api/v1/tasks?limit=2" \
    -H "Authorization: Bearer $TOKEN" || true
else
  echo "[signoz-smoke] warn: no JWT (API down or wrong creds)"
fi

if docker compose -f "$ROOT/docker-compose.yml" ps worker --status running -q 2>/dev/null | grep -q .; then
  docker compose -f "$ROOT/docker-compose.yml" exec -T worker python -c "
import os, logging, time, uuid
os.environ.setdefault('OTEL_ENABLED','true')
os.environ.setdefault('OTEL_EXPORTER_OTLP_ENDPOINT','http://zovark-signoz-collector:4318')
from tracing import init_tracing, get_tracer
init_tracing()
rid = '$RUN_ID'
t = get_tracer()
with t.start_as_current_span('signoz.smoke.script') as s:
    s.set_attribute('signoz.smoke.run_id', rid)
logging.getLogger('zovark_worker').warning('signoz_smoke_script run_id=%s', rid)
time.sleep(0.3)
print('[signoz-smoke] worker span+log emitted', rid)
" 2>/dev/null || echo "[signoz-smoke] worker exec skipped"
else
  echo "[signoz-smoke] worker not running — use: docker compose run --rm worker pytest tests/test_signoz_telemetry.py"
fi

echo "[signoz-smoke] done — check SigNoz: Services zovark-api, zovark-worker; search traces signoz.smoke / POST login"
