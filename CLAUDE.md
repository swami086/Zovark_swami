# HYDRA — Autonomous AI SOC Platform

> Air-gapped, on-premise security operations center powered by local LLMs.
> Receives SIEM alerts → generates investigation code → executes in sandbox → delivers structured verdicts.

## Quick Reference

- **Version:** post v1.0.0-rc1 (latest: `2f99e9c`)
- **Status:** V2 Pipeline OPERATIONAL — 100/100 stress test, 10/10 LLM test
- **Stack:** Go API + Python Temporal Worker + React Dashboard + PostgreSQL + Redis + NATS + llama.cpp (Qwen2.5-14B)
- **Pipeline:** V2 5-stage (1392 lines) — replaced legacy (2916 lines)
- **Tests:** 44 Go + 179 Python + 15 V2 pipeline = 238 test functions
- **Services:** 8 Docker containers (core stack, monitoring optional)

## Architecture (V2 Pipeline)

```
SIEM Alert → Go API (:8090) → Temporal: InvestigationWorkflowV2 →
  Stage 1 INGEST:  dedup (Redis) → PII mask → skill retrieval     [NO LLM]
  Stage 2 ANALYZE: template fill OR full LLM code generation       [LLM ①]
  Stage 3 EXECUTE: AST prefilter → Docker sandbox                  [NO LLM]
  Stage 4 ASSESS:  verdict → LLM summary → FP confidence           [LLM ②]
  Stage 5 STORE:   agent_tasks + investigations + memory            [NO LLM]
  → Structured Verdict (findings, IOCs, recommendations, risk score)
```

LLM contained in exactly 2 files: `worker/stages/analyze.py` + `worker/stages/assess.py`

## Directory Map

```
hydra-mvp/
├── api/                    # Go REST API (45 files) — auth, handlers, middleware, RBAC
├── worker/                 # Python Temporal worker — investigation pipeline
│   ├── stages/                # V2 pipeline (5 stages, 1392 lines total)
│   │   ├── __init__.py        # Typed dataclass contracts (IngestOutput, AnalyzeOutput, etc.)
│   │   ├── ingest.py          # Stage 1: dedup, PII mask, skill retrieval (NO LLM)
│   │   ├── analyze.py         # Stage 2: template/LLM/stub code generation (LLM HERE)
│   │   ├── execute.py         # Stage 3: AST prefilter + Docker sandbox (NO LLM)
│   │   ├── assess.py          # Stage 4: verdict + LLM summary (LLM HERE)
│   │   ├── store.py           # Stage 5: DB writes (NO LLM)
│   │   ├── investigation_workflow.py  # InvestigationWorkflowV2 (~40 lines)
│   │   └── register.py        # get_v2_activities() + get_v2_workflows()
│   ├── _legacy_activities.py  # Shared activities (fetch_task, log_audit, etc.)
│   ├── activities/            # Package re-exports shared activities
│   ├── workflows/             # Non-investigation workflows (feedback/KEV/hydra)
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

- **V2 Investigation pipeline:** 100/100 FAST_FILL, 10/10 with LLM, avg 52s/investigation
- **Auth flow:** Register → login → JWT (15min) → refresh (7d) → RBAC (admin/analyst/viewer)
- **LLM:** Qwen2.5-14B-Instruct Q4_K_M via llama.cpp (native Windows, NOT Docker)
- **LITELLM_URL:** `http://host.docker.internal:11434/v1/chat/completions` (bypasses LiteLLM container)
- **Sandbox:** Docker with AST prefilter, network isolation, read-only fs, cap-drop ALL
- **Database:** 76+ tables, pgvector embeddings, connection pooling via PgBouncer
- **DPO:** Trained adapter available (`models/hydra-dpo-adapter/`, 48MB), GGUF at `models/hydra-dpo-Q4_K_M.gguf`
- **V2 unit tests:** 15/15 passing in <1s

## Performance (V2 Pipeline)

| Test | Completion | Avg Time |
|------|-----------|----------|
| V2 + FAST_FILL (100 investigations) | 100/100 | <2s each |
| V2 + LLM (10 investigations) | 10/10 | 52s each |
| Legacy pipeline (100 investigations) | 61/100 | 368s each |

## Known Issues

1. **NATS hostname resolution** — Non-fatal warning on worker startup. Consumer initializes despite it.
2. **Old Temporal workflows** — Stale `ExecuteTaskWorkflow` replays in Temporal history cause non-blocking errors. Terminate via `tctl workflow terminate`.
3. **`investigations` table source constraint** — Only allows `production`, `bootstrap`, `synthetic`. V2 uses `production`.
4. **`investigation_memory` table** — Name is SINGULAR. Code that references `investigation_memories` (plural) silently fails.
5. **`fetch_task` dependency** — V2 workflow still calls legacy `fetch_task` by string name. Tech debt — should be moved to stages/ingest.py.

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
- **New V2 activities:** Add to the appropriate `worker/stages/*.py` file, register in `worker/stages/register.py`
- **New workflows:** Add to `worker/stages/`, register in `worker/stages/register.py`
- **Legacy activities:** Still in `worker/_legacy_activities.py` (shared by non-investigation workflows). Do NOT add new code here.
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
# Set HYDRA_ADMIN_EMAIL and HYDRA_ADMIN_PASSWORD env vars
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'"${HYDRA_ADMIN_EMAIL}"'","password":"'"${HYDRA_ADMIN_PASSWORD}"'"}' | \
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

## Key Docs

| Doc | Path |
|-----|------|
| Architecture Snapshot | `docs/ARCHITECTURE_SNAPSHOT.md` |
| Session Prompts | `docs/SESSION_PROMPTS.md` |
| Pipeline Map | `docs/pipeline_map.md` |
| Pipeline Stages | `docs/pipeline_stages.md` |
| API Spec (v1.2.0) | `docs/openapi.yaml` |
| Security Audit | `docs/SECURITY_AUDIT_v0.10.0.md` |

## Pending Work (Priority Order)

1. **Remove `_legacy_activities.py`** — Migrate shared activities (fetch_task, log_audit, etc.) to V2 modules
2. **Multi-worker scaling test** — Run V2 with `docker compose --scale worker=3`
3. **DPO Phase 2** — Expand training data from 33 to 200+ pairs, retrain
4. **K8s cluster test** — Deploy to real cluster via `scripts/k8s_cluster_test.sh`
5. **Full corpus benchmark** — Run 70 labeled alerts through V2 pipeline
