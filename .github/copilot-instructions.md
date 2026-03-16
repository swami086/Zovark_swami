# HYDRA Copilot Instructions

Read `CLAUDE.md` at repo root for full project context.

## Conventions

- **Go:** `gofmt`, package `main` for API binary, errors via `respondInternalError()`
- **Python:** `flake8`, type hints preferred, `@activity.defn` / `@workflow.defn` for Temporal
- **Commits:** `feat:`, `fix:`, `security:`, `test:`, `docs:`, `release:` prefixes
- **Migrations:** Sequential numbered `NNN_description.sql`, idempotent (IF NOT EXISTS)
- **Tests:** Go: `*_test.go` in same package. Python: `worker/tests/test_*.py`
- **Config:** All secrets via env vars. `.env.example` is the contract. Never hardcode.
- **DB queries:** Always tenant-scoped (WHERE tenant_id = $X)
- **LLM calls:** Always through LiteLLM (port 4000), never direct to model
- **Error responses:** Never leak table names, SQL, or stack traces to clients

## Architecture

- Go API in `api/` (Gin framework, 61+ endpoints)
- Python worker in `worker/` (Temporal SDK, 16 workflows, 104 activities)
- PostgreSQL 16 + pgvector for all persistent state
- Redis 7 for ephemeral state (rate limits, cache)
- NATS JetStream for real-time events
- Docker sandbox for LLM-generated code execution
