# Zovark Copilot Instructions

Read `CLAUDE.md` at repo root for full project context.

## Conventions

- **Go:** `gofmt`, package `main` for API binary, errors via `respondInternalError()`
- **Python:** `flake8`, type hints preferred, `@activity.defn` / `@workflow.defn` for Temporal
- **Commits:** `feat:`, `fix:`, `security:`, `test:`, `docs:`, `release:` prefixes
- **Migrations:** Sequential numbered `NNN_description.sql`, idempotent (IF NOT EXISTS)
- **Tests:** Go: `*_test.go` in same package. Python: `worker/tests/test_*.py`
- **Config:** All secrets via env vars. `.env.example` is the contract. Never hardcode.
- **DB queries:** Always tenant-scoped (WHERE tenant_id = $X)
- **LLM calls:** Always through `worker/stages/llm_gateway.py` via `ZOVARK_LLM_ENDPOINT` (direct to Ollama, no proxy)
- **Error responses:** Never leak table names, SQL, or stack traces to clients

> **Note:** LiteLLM was previously used as an LLM proxy (port 4000) but has been removed due to supply chain risk (PyPI compromise). All LLM calls now go directly to Ollama via `ZOVARK_LLM_ENDPOINT`.

## Architecture

- Go API in `api/` (Gin framework, 90+ endpoints)
- Python worker in `worker/` (Temporal SDK, V2 5-stage pipeline)
- PostgreSQL 16 + pgvector for all persistent state
- Redis 7 for ephemeral state (rate limits, cache, dedup)
- NATS JetStream for real-time events (optional)
- Docker sandbox for LLM-generated code execution
