# HYDRA — Session Prompts for Claude Code

## Prompt 1: Fresh Session Start
Paste this at the beginning of every new Claude Code session:

```bash
cat docs/ARCHITECTURE_SNAPSHOT.md
git log --oneline -5
docker compose ps | head -20
docker compose exec api printenv HYDRA_WORKFLOW_VERSION
docker compose logs worker --tail 3 2>&1 | grep -v NATS
curl -s http://localhost:11434/v1/models | head -3
```

Report: git HEAD, containers, V2 active, worker healthy, LLM loaded.

## Prompt 2: Smoke Test (one investigation with LLM)

```bash
docker compose exec redis redis-cli -a ${REDIS_PASSWORD} FLUSHDB 2>/dev/null

TOKEN=$(curl -s http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'"${HYDRA_ADMIN_EMAIL}"'","password":"'"${HYDRA_ADMIN_PASSWORD}"'"}' | \
  sed 's/.*"token":"\([^"]*\)".*/\1/')

TID=$(curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"phishing_investigation","input":{"prompt":"Smoke test","severity":"high","siem_event":{"title":"Phishing","source_ip":"10.0.0.99","destination_ip":"203.0.113.50","hostname":"WS-SMOKE","username":"alice","rule_name":"Phishing_Smoke","raw_log":"GET /login.php?token=abc123 HTTP/1.1 Host: secure-update.xyz"}}}' | \
  sed 's/.*"task_id":"\([^"]*\)".*/\1/')

echo "Task: $TID"

for i in $(seq 1 15); do
  S=$(curl -s "http://localhost:8090/api/v1/tasks/$TID" \
    -H "Authorization: Bearer $TOKEN" | grep -o '"status":"[^"]*"' | head -1)
  echo "[$i] $S"
  echo "$S" | grep -qE "completed|failed" && break
  sleep 10
done
```

Expected: completed in ~50-60s with IOCs and findings.

## Prompt 3: Batch Test (10 or 100 investigations)

```bash
docker compose exec redis redis-cli -a ${REDIS_PASSWORD} FLUSHDB 2>/dev/null
docker compose exec -T worker python -c "import sys; open('batch_runner.py','w').write(sys.stdin.read())" < scripts/batch_runner.py
docker compose exec -T worker python -c "import sys; open('alert_corpus_100.py','w').write(sys.stdin.read())" < scripts/alert_corpus_100.py
docker compose exec worker python -c "exec(open('alert_corpus_100.py').read().replace('scripts/alert_corpus_100.json', 'alert_corpus_100.json'))"
docker compose exec worker rm -f batch_progress.json batch_results_100.json
docker compose exec -e API_URL=http://hydra-api:8090 -e CORPUS=alert_corpus_100.json worker python batch_runner.py --limit 10
```

## Prompt 4: FAST_FILL Stress Test (no LLM, plumbing only)

```bash
HYDRA_FAST_FILL=true docker compose up -d worker
sleep 20
docker compose exec worker printenv HYDRA_FAST_FILL
# Then run Prompt 3 above.
# After test:
docker compose up -d worker  # restarts without FAST_FILL
```

## Prompt 5: Verify V2 Pipeline Integrity

```bash
wc -l worker/stages/*.py
grep -n "httpx\|LITELLM_URL\|urlopen" worker/stages/ingest.py worker/stages/execute.py worker/stages/store.py || echo "CLEAN"
grep -n "@activity.defn" worker/stages/*.py
cat worker/stages/investigation_workflow.py
docker compose exec -e HYDRA_FAST_FILL=true -e DEDUP_ENABLED=false worker python -m pytest test_pipeline_v2.py -v --tb=short 2>&1 | tail -20
```

## Prompt 6: Check for Legacy Contamination

```bash
grep -rn "from.*_legacy\|import.*_legacy" worker/stages/*.py
grep -rn "_legacy" worker/stages/investigation_workflow.py
# These must return ZERO matches (docstring mentions don't count).
# V2 stages must not import legacy code.
```

## Prompt 7: Switch Back to Legacy (emergency rollback)

```bash
# In docker-compose.yml, change:
#   HYDRA_WORKFLOW_VERSION=ExecuteTaskWorkflow
# Then restore _legacy_workflows.py from git:
#   git checkout HEAD~1 -- worker/_legacy_workflows.py
# Rebuild and restart:
#   docker compose build worker && docker compose up -d worker
```

## Key Reference
- Admin: `${HYDRA_ADMIN_EMAIL}` / `${HYDRA_ADMIN_PASSWORD}` (set in .env)
- API: `http://localhost:8090`
- LLM: `http://localhost:11434` (llama-server, native Windows)
- Redis: password `${REDIS_PASSWORD}` (set in .env)
- Workflow default: `InvestigationWorkflowV2`
- FAST_FILL: set `HYDRA_FAST_FILL=true` on `docker compose up` for stress tests
