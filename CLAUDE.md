# HYDRA — AI-Powered SOC Automation Platform

## What This Is

HYDRA receives security alerts from any SIEM, uses locally-hosted LLMs to generate investigation code, executes that code in sandboxed containers, and returns structured findings with risk scores, entity graphs, and incident reports. Zero mandatory cloud dependencies. Air-gap capable.

## Quick Reference

- **Version:** v1.0.0-rc1
- **Status:** Runtime-validated release candidate
- **Total LOC:** ~74,800 (Go 10.6k + Python 42k + TypeScript 8.9k + SQL 3.2k + Shell 4.1k + YAML 6k)
- **Tests:** 44 Go + 302 Python = 346 passing
- **Services:** 17 Docker containers

## Architecture

```
Dashboard (React 19 :3000)
    ↓ REST
Go API Gateway (Gin :8090)
    ↓           ↓          ↓         ↓
PostgreSQL   Temporal    Redis     NATS
(16+pgvector) (1.24.2)  (7-alpine) (JetStream)
    ↓           ↓
Python Worker (Temporal SDK)
    ↓           ↓
LiteLLM → vLLM/Ollama    Docker Sandbox (no-net, seccomp, 30s kill)
```

## Directory Map

```
hydra-mvp/
├── api/                # Go API gateway (48 files) — auth, RBAC, handlers, middleware
├── worker/             # Python Temporal worker (132 files) — investigation pipeline
│   ├── activities/     #   Network analysis (Zeek)
│   ├── bootstrap/      #   MITRE/CISA corpus loading
│   ├── database/       #   Connection pool manager (psycopg2 ThreadedConnectionPool)
│   ├── detection/      #   Sigma rule generation
│   ├── finetuning/     #   Training data pipeline
│   ├── intelligence/   #   Blast radius, FP analysis, cross-tenant intel
│   ├── investigation/  #   DeepLog LSTM, enrichment
│   ├── prompts/        #   16 LLM prompt templates
│   ├── reporting/      #   Incident reports (MD + PDF)
│   ├── response/       #   SOAR playbooks + template resolver
│   ├── security/       #   Injection detection, sanitization
│   ├── skills/         #   Deobfuscation sandbox
│   ├── sre/            #   Self-healing agent
│   ├── tests/          #   302 unit tests
│   ├── threat_intel/   #   Attack surface recon
│   └── workflows/      #   Feedback aggregation, KEV processing
├── dashboard/          # React 19 + Vite 7 + Tailwind 4 (55 files, 15 pages)
├── mcp-server/         # TypeScript MCP server (25 files — 7 tools, 7 resources, 6 prompts)
├── sandbox/            # AST prefilter + seccomp + kill timer (4 files)
├── migrations/         # 39 SQL migration files
├── k8s/                # Kubernetes manifests (32 files — dev/prod/airgap overlays)
├── helm/               # Helm charts for K8s deployment
├── terraform/          # AWS/GCP infrastructure-as-code
├── config/             # PostgreSQL configuration (pg_hba.conf, postgresql.conf)
├── proxy/              # Squid egress proxy configuration
├── monitoring/         # Prometheus rules + Grafana dashboards (9 files)
├── scripts/            # 35 operational scripts
│   └── pov/            # 48-hour Proof of Value package
├── security-fixes/     # Security remediation specs and reports (18 files)
├── sdk/                # Client SDK (6 files)
├── tests/              # Integration tests + test corpus (83 files)
├── docs/               # Architecture, deployment, security docs (23 files)
├── temporal-config/    # Temporal workflow engine configuration
└── local_models/       # Downloaded LLM weights (Qwen2.5 + nomic-embed)
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | Go 1.22 + Gin (61+ endpoints) |
| Worker | Python 3.11 + Temporal SDK (16 workflows, 104 activities) |
| Database | PostgreSQL 16 + pgvector (67 tables, 39 migrations) |
| Cache | Redis 7 via go-redis/v9 (pooled) |
| Workflows | Temporal 1.24.2 |
| Events | NATS JetStream |
| LLM Gateway | LiteLLM (multi-provider fallback) |
| Inference | vLLM (Qwen2.5-1.5B-AWQ) / Ollama (air-gap) |
| Embeddings | nomic-embed-text-v1.5 (768-dim) |
| Frontend | React 19 + Vite 7 + Tailwind 4 |
| MCP | TypeScript + @modelcontextprotocol/sdk |
| Object Storage | MinIO |
| Monitoring | Prometheus + Grafana + Jaeger |

## How to Run

```bash
# Quick deploy (generates secrets, boots 17 services, runs migrations)
bash scripts/pov/deploy.sh

# Verify
curl http://localhost:8090/health

# Open dashboard at http://localhost:3000
```

## How to Test

```bash
# Go tests (44 tests) — requires golang:1.22 or Docker
cd api && go test -v -count=1 ./...

# Python tests (302 tests) — requires Python 3.11
cd worker && python -m pytest tests/ -v

# Integration (requires Docker stack running)
python tests/integration/test_full_investigation.py
```

## API

61+ REST endpoints. Full OpenAPI spec at `docs/openapi.yaml` (v1.2.0).

Key endpoints:
- `POST /api/v1/auth/login` — authenticate (returns JWT)
- `POST /api/v1/auth/register` — create user (requires email, password, display_name, tenant_id)
- `POST /api/v1/tasks` — submit investigation task
- `GET /api/v1/tasks/{id}` — get investigation result
- `GET /api/v1/tasks/{id}/stream` — SSE stream investigation progress
- `POST /api/v1/siem-alerts/{id}/investigate` — investigate a SIEM alert
- `GET /api/v1/stats` — dashboard statistics
- `GET /api/v1/analytics/feedback/summary` — feedback analytics

Auth: JWT access token (15min) + httpOnly refresh cookie (7d). RBAC roles: admin, analyst, viewer.

## Database

67 tables. PostgreSQL 16 + pgvector. Migrations in `migrations/` (001-039).

Key tables: `agent_tasks`, `investigations`, `entities`, `entity_edges`, `siem_alerts`, `detection_candidates`, `response_playbooks`, `investigation_feedback`, `users`, `tenants`

## Temporal Workflows

16 workflows, 104 activities. Task queue: `hydra-tasks`.

Core: `ExecuteTaskWorkflow` — the main investigation pipeline (alert → LLM code gen → AST validation → sandbox execution → entity extraction → report).

## Security

7-layer defense: network perimeter → JWT auth → RBAC → PII masking → sandbox (AST + seccomp + no-net + kill timer) → LLM safety (injection detection, adversarial review, approval gates) → audit logging.

30/30 security audit findings resolved. See `docs/SECURITY_AUDIT_v0.10.0.md`.

## Key Docs

| Doc | Path |
|-----|------|
| Architecture (deep) | `docs/ARCHITECTURE.md` |
| API Spec | `docs/openapi.yaml` |
| Deployment | `docs/DEPLOYMENT_GUIDE.md` |
| Security Audit | `docs/SECURITY_AUDIT_v0.10.0.md` |
| Changelog | `CHANGELOG.md` |
| Release Notes | `RELEASE_NOTES.md` |
| PoV Playbook | `scripts/pov/README.md` |
| Codebase Census | `docs/CODEBASE_CENSUS.md` |
| Validation Report | `VALIDATION_REPORT.md` |

## Version History

```
v1.0.0-rc1  Release candidate (validated: 346 tests, 17 services healthy)
v0.18.0     Documentation + CHANGELOG
v0.17.0     48-hour PoV package
v0.16.0     Deployment hardening (CORS, vLLM, OpenAPI, legacy cleanup)
v0.15.0     Architectural fixes + operational readiness
v0.14.0     Testing + CI (44 Go + 302 Python tests, migration runner)
v0.13.0     Platform features (ML detection, Zeek, WebSocket, 4 workflows)
v0.12.0     Defense-in-depth (Vault, egress proxy, sanitizer, adversarial, MCP gate)
v0.11.0     Security remediation (30/30 audit findings)
v0.10.1     Critical security fixes (JWT, httpOnly, injection blocking)
```

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
- **Branches:** `master` is main development branch
