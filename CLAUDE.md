# HYDRA — Autonomous AI SOC Platform

> Air-gapped, on-premise security operations center powered by local LLMs.
> Receives SIEM alerts → generates investigation code → executes in sandbox → delivers structured verdicts.

## Quick Reference

- **Version:** post v1.0.0-rc1 (latest: `e17ccad`)
- **Status:** Pipeline OPERATIONAL — investigations complete end-to-end
- **Stack:** Go API + Python Temporal Worker + React Dashboard + PostgreSQL + Redis + NATS + LiteLLM + Ollama
- **LOC:** Go 45 files, Python 124 files, TypeScript 33 files, 40 migrations
- **Tests:** 44 Go + 179 Python = 223 test functions passing
- **Services:** 17 Docker containers running (11 core + 6 monitoring/exporters)

## Architecture

```
SIEM Alert → Go API (:8090, auth/RBAC/rate-limit) → PostgreSQL → Temporal Workflow →
  → Skill Matching → PII Masking → LLM (Ollama via LiteLLM) → fill_skill_parameters →
  → render_skill_template → AST Prefilter → Adversarial Review → Docker Sandbox →
  → Entity Extraction → Knowledge Graph → Sigma Rule Gen → Investigation Memory →
  → Structured Verdict (findings, IOCs, recommendations, risk score)
```

## Directory Map

```
hydra-mvp/
├── api/                    # Go REST API (45 files) — auth, handlers, middleware, RBAC
├── worker/                 # Python Temporal worker (124 files) — investigation pipeline
│   ├── _legacy_activities.py  # 110 @activity.defn functions (main activities file)
│   ├── _legacy_workflows.py   # ExecuteTaskWorkflow (main workflow)
│   ├── activities/            # Package re-exports from _legacy_activities.py + network_analysis
│   ├── workflows/             # Package re-exports from _legacy_workflows.py + feedback/KEV/hydra
│   ├── database/              # Connection pool manager (psycopg2 ThreadedConnectionPool)
│   ├── detection/             # Sigma rule generation
│   ├── intelligence/          # Blast radius, FP analysis, cross-tenant
│   ├── investigation/         # DeepLog LSTM, memory
│   ├── response/              # SOAR playbooks + template resolver
│   ├── security/              # Injection detection, adversarial review, sanitization
│   ├── bootstrap/             # MITRE/CISA corpus loading
│   └── tests/                 # 179 test functions
├── dashboard/              # React 19 + Vite 7 + Tailwind 4 (33 TS/TSX files)
├── dpo/                    # DPO training pipeline (6 files) — forge, prompts, validators
├── mcp-server/             # TypeScript MCP server (25 files)
├── sandbox/                # AST prefilter + seccomp + kill timer (6 files)
├── migrations/             # PostgreSQL migrations (40 files, 001-040)
├── k8s/                    # Kubernetes manifests (32 files — dev/prod/airgap overlays)
├── scripts/                # Utility scripts (40 files) — accuracy, deploy, census
├── docs/                   # Documentation (34 files)
├── helm/                   # Helm charts for K8s deployment
├── terraform/              # IaC for AWS/GCP
├── config/                 # PostgreSQL configuration
├── security-fixes/         # Remediation specs (historical)
├── tests/                  # Integration tests + test corpus + ground truth
├── litellm_config.yaml     # LLM routing (fast → Ollama qwen2.5:14b)
├── docker-compose.yml      # 11 core services + monitoring stack
└── docker-compose.enterprise.yml  # 48GB+ VRAM override (7B + 32B models)
```

## Version History

| Version | Commit | What Changed |
|---------|--------|-------------|
| v0.10.1 | `f1974bd` | Initial security fixes (JWT, OIDC, httpOnly cookies) |
| v0.11.0 | `7bf17e9` | 30/30 security audit findings resolved |
| v0.12.0 | `2f25c32` | 5 hardening features (Vault, egress proxy, adversarial review, MCP gate) |
| v0.13.0 | `2785bc9` | 10 features (DeepLog, Zeek, WebSocket, DB pools, attack surface) |
| v0.14.0 | `11539af` | Test infrastructure (44 Go + Python tests, CI pipeline, migration runner) |
| v0.15.0 | `83d1f34` | Architectural fixes + operational readiness (template resolver, feedback, KEV) |
| v0.16.0 | `e31d329` | Deployment hardening (CORS, vLLM, OpenAPI v1.2.0, legacy cleanup) |
| v0.17.0 | `63df379` | 48-hour PoV package (SIEM import, report generator, deploy script) |
| v0.18.0 | `0128f60` | CHANGELOG |
| v1.0.0-rc1 | `377db3c` | Release candidate — runtime validated |
| post-rc1 | `0f01672` | Compile fixes (missing json import, unused fmt import, NATS flags) |
| post-rc1 | `388435a` | Project standardization (CLAUDE.md, AGENTS.md, .cursorrules, census) |
| post-rc1 | `d467057` | CTO review response (accuracy benchmark, enterprise profiles, model tiers) |
| post-rc1 | `dffc3d5` | DPO pipeline Phase 0 (forge, prompts, validators, compressor, sandbox endpoint) |
| post-rc1 | `820e456` | Pipeline debug — 5 root causes fixed, investigations complete end-to-end |
| post-rc1 | `e17ccad` | Updated baseline — 7 investigations scored |

## Current State (What Works)

- **Investigation pipeline:** OPERATIONAL — submit alert → structured verdict with findings, IOCs, risk score
- **Auth flow:** Register → login → JWT (15min) → refresh (7d) → RBAC (admin/analyst/viewer)
- **LLM routing:** Ollama (qwen2.5:14b) via LiteLLM on local GPU
- **Sandbox:** Docker-in-Docker with AST prefilter v2, network isolation, read-only fs, cap-drop ALL
- **Database:** 76 tables, pgvector embeddings, connection pooling via PgBouncer
- **17 Docker services:** all healthy and running
- **7 completed investigations** with baseline metrics
- **DPO pipeline Phase 0:** committed (forge + prompts + validators + compressor)

## Baseline Accuracy (7 investigations)

| Metric | Value |
|--------|-------|
| Code generation | 100% (7/7) |
| Mean risk score | 76 |
| Findings rate | 86% (6/7) |
| IOC extraction | 29% (2/7) |
| Mean execution | 30.9s |

## Known Issues (Be Honest)

1. **IOC extraction is weak (29%)** — DPO training targets this specifically
2. **Adversarial review passes through on timeout** — Intentional: AST prefilter + Docker sandbox are primary security layers. Review LLM via urllib times out against Ollama.
3. **LiteLLM ↔ Redis auth errors** — Non-fatal (caching only). Fix: add REDIS_PASSWORD to LiteLLM env.
4. **NATS hostname resolution** — Non-fatal warning on worker startup. Consumer initializes despite it.
5. **fill_skill_parameters errors silently** — Ollama doesn't support `response_format:json_object`. Function catches and returns defaults. Investigation continues.
6. **Skill template fix not in migration** — The `import os, sys` removal was via direct SQL UPDATE. Need migration for reproducibility.
7. **429 with Ollama** — Single-threaded inference. Multi-step investigations hit rate limits. Complete but take 55s instead of 30s.

## Model Tiers

| Tier | Purpose | Model | Hardware |
|------|---------|-------|----------|
| Fast | Triage, classification | Local qwen2.5:14b via Ollama | Any NVIDIA GPU |
| Standard | Full investigation | 32B or cloud 70B | A6000 (48GB) or cloud API |
| Reasoning | Complex analysis | 70B+ or cloud | A100 (80GB) or cloud API |

See `docs/MODEL_TIER_STRATEGY.md` and `docs/HARDWARE_REQUIREMENTS.md`.

## Coding Conventions

- **Tenant isolation:** Every DB query MUST include `tenant_id` in WHERE clause
- **Error handling (Go):** Use `respondInternalError()` — never expose `err.Error()` to clients
- **LLM calls:** Always through LiteLLM (`LITELLM_URL`), never call Ollama directly
- **Sandbox code:** Must pass AST prefilter — no `os`, `sys`, `subprocess`, `socket`, dunder traversal
- **Skill templates:** Must NOT import `os`, `sys`, `subprocess`, `socket` (blocked by AST prefilter v2)
- **New activities:** Add to `worker/_legacy_activities.py`, re-export in `worker/activities/__init__.py`, register in `main.py`
- **New workflows:** Add to `worker/_legacy_workflows.py`, re-export in `worker/workflows/__init__.py`, register in `main.py`
- **Migrations:** Sequential in `migrations/`, apply via `docker compose exec -T postgres psql -U hydra -d hydra < migrations/NNN_name.sql`
- **After Python changes:** `docker compose build worker && docker compose up -d worker`
- **After Go changes:** `docker compose build api && docker compose up -d api`

## How to Run

```bash
# Start all services
docker compose up -d

# Verify health
curl -s http://localhost:8090/health

# Login
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' | \
  sed 's/.*"token":"\([^"]*\)".*/\1/')

# Submit investigation
curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"brute_force","input":{"prompt":"Analyze SSH brute force from 10.0.0.99","severity":"high"}}'

# Poll for result
curl -s http://localhost:8090/api/v1/tasks/<TASK_ID> -H "Authorization: Bearer $TOKEN"
```

## How to Test

```bash
# Go tests (44 test functions)
cd api && go test -v -count=1 ./...

# Python tests (179 test functions)
cd worker && python -m pytest tests/ -v

# Or via Docker
docker compose exec worker python -m pytest tests/ -v
```

## Key Docs

| Doc | Path |
|-----|------|
| Architecture | `docs/ARCHITECTURE.md` |
| API Spec (v1.2.0) | `docs/openapi.yaml` |
| Security Audit | `docs/SECURITY_AUDIT_v0.10.0.md` |
| Model Tiers | `docs/MODEL_TIER_STRATEGY.md` |
| Hardware Requirements | `docs/HARDWARE_REQUIREMENTS.md` |
| Accuracy Report | `docs/ACCURACY_REPORT.md` |
| Baseline Accuracy | `docs/BASELINE_ACCURACY.md` |
| PoV Playbook | `scripts/pov/README.md` |
| Changelog | `CHANGELOG.md` |
| Project Status | `docs/PROJECT_STATUS.md` |

## DPO Training Pipeline (Phase 0 complete)

Files in `dpo/`: `dpo_forge.py`, `prompts.py`, `validators.py`, `log_compressor.py`, `seed_database.json`, `requirements.txt`

```bash
# Phase 2: Generate training data (overnight, ~$50 Kimi API)
export KIMI_API_KEY=your_key
python dpo/dpo_forge.py

# Phase 3: Train (4-6 hours on RTX 3050)
pip install -r dpo/requirements.txt
python scripts/dpo_train.py

# Phase 4: Measure delta
python scripts/accuracy_benchmark.py --model hydra_aligned_1.5b
```

## Pending Work (Priority Order)

1. **DPO Phase 2-4** — Generate training data, train model, measure accuracy delta
2. **Full corpus benchmark** — Run accuracy_benchmark.py against all 70 labeled alerts
3. **Skill template migration** — Persist `import os,sys` removal as migration 041
4. **LiteLLM Redis auth** — Add REDIS_PASSWORD to litellm env in docker-compose
5. **K8s cluster test** — Deploy to real cluster via `scripts/k8s_cluster_test.sh`
