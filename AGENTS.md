# Agent Instructions

This file provides context for AI coding agents working on HYDRA.

## Before Making Changes

1. Read `CLAUDE.md` for project overview
2. Run `bash scripts/census.sh` to verify current state
3. Check `CHANGELOG.md` for recent changes
4. Run tests before and after: `cd api && go test ./...` and `cd worker && pytest tests/`

## Architecture Decisions

- Temporal for all async work — never use raw goroutines or threading for investigation pipeline
- PostgreSQL + pgvector for all persistent state — no separate vector DB
- LiteLLM as single gateway to all LLM providers — never call models directly
- Docker sandbox for code execution — never run LLM-generated code in worker process
- NATS for real-time events — never poll the database for status updates
- Redis for ephemeral state only (rate limits, cache) — never for durable data
- go-redis/v9 for Redis access in Go — never raw TCP/RESP parsing
- psycopg2 ThreadedConnectionPool for DB in Python — never per-call psycopg2.connect()

## Common Tasks

### Add a new API endpoint
1. Add handler in `api/` (group with related handlers by domain)
2. Register route in `api/main.go`
3. Add test in `api/*_test.go`
4. Update `docs/openapi.yaml`

### Add a new Temporal activity
1. Create function with `@activity.defn` in appropriate `worker/` subdirectory
2. Import and register in `worker/main.py` activities list
3. Update the activities count in the log line
4. Add test in `worker/tests/test_*.py`

### Add a new Temporal workflow
1. Create class with `@workflow.defn` in `worker/workflows/`
2. Import and register in `worker/main.py` workflows list
3. Update the workflows count in the log line

### Add a new migration
1. Create `migrations/NNN_description.sql` (next number after 039)
2. Use IF NOT EXISTS / IF EXISTS for idempotency
3. Apply: `docker compose exec hydra-api ./hydra-api migrate up`

### Run the 48-hour PoV
1. `bash scripts/pov/deploy.sh`
2. `python scripts/pov/import_alerts.py --format splunk --file alerts.csv --tenant-id <id>`
3. `python scripts/pov/generate_report.py --tenant-id <id> --output report.html`

### Regenerate codebase census
```bash
bash scripts/census.sh
```

## File Count Reference

- Go source files: 48 in `api/`
- Python source files: 132 in `worker/`
- SQL migrations: 39 in `migrations/`
- Dashboard: 55 files in `dashboard/`
- K8s manifests: 32 files in `k8s/`
- Tests: 83 files in `tests/`, plus `worker/tests/` and `api/*_test.go`
