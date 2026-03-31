# Changelog

## v3.0.0 (March 2026)

### Architecture
- Replaced LLM code generation with deterministic tool-calling
- 34 investigation tools across 7 categories (extraction, analysis, parsing, scoring, detection, enrichment)
- 24 saved investigation plans for known attack types
- Path A (saved plan): ~50ms, no LLM required
- Path C (novel alert): ~15s, 3B tool selection + 8B synthesis
- Path D: per-investigation fallback from v3 tools to v2 sandbox
- v2 Docker sandbox preserved behind `ZOVARK_EXECUTION_MODE=sandbox`
- Governance layer: observe/assist/autonomous modes per tenant/task_type

### Benchmark
- 100% detection rate (157/157 attacks correctly identified)
- 0% false positive rate (0/8 benign incorrectly flagged)
- 0% Path D fallback (all tools executed successfully)
- 0% error rate

### Security
- 152 red team experiments, 60 bypasses found and patched
- v3 red team: 21 tests across 5 categories, 0 critical vulnerabilities
- 25 input sanitizer patterns + Unicode NFKC normalization
- 54 RAW_LOG_ATTACK_PATTERNS for content-based routing override
- IOC provenance validation, suppression phrase detection

### Observability
- OpenTelemetry distributed tracing across full pipeline
- Signoz backend (self-hosted, ClickHouse-backed, air-gap compatible)
- Per-stage spans: ingest, analyze, execute, assess, govern, store
- Per-tool spans with duration, success, risk_score attributes
- LLM call spans with model, tokens, latency
- Path D fallback spans (critical alert signal)
- Start: `docker compose --profile tracing up -d` → http://localhost:3301

### Infrastructure
- PostgreSQL RLS on 11 tables with tenant isolation
- Template promotion with 2-person quorum approval
- Healer: synthetic login checks, async health monitoring
- SSE real-time dashboard updates via PostgreSQL LISTEN/NOTIFY
- Readiness probe: `GET /ready` checks DB + Redis + Temporal
- Request tracing: UUID trace_id from ingest through store

## v2.1 (March 2026)

### Wartime Sprint (10 Missions)
- Docker socket proxy, promotion quorum, RLS, request tracing
- Fail-closed LLM degradation, flight data recorder
- CMMC compliance engine, healer async, SSE dashboard

### AutoResearch
- Autonomous red team: 152 experiments, 144 bypasses found
- Template engineer: 10/10 attack types, all fitness >0.98

## v2.0 (March 2026)
- Two-model routing (Meta Llama 3.2 3B + 3.1 8B)
- 25 skill templates, benign routing, code cache
- Security hardening: AST prefilter, sandbox, input sanitizer
- SOC War Room dashboard, fleet agent self-healer
