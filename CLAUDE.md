# Zovark v2.0 — Autonomous AI SOC Agent

> Air-gapped SOC investigation platform for regulated enterprises (GDPR/HIPAA/CMMC).
> Receives SIEM alerts, generates investigation code via local LLMs, executes in sandbox, delivers structured verdicts.
> Rebranded from HYDRA. Repo directory is still `hydra-mvp`. All source code uses "Zovark" branding.

## Quick Reference

| Field | Value |
|-------|-------|
| Version | v2.0 — 215 commits on master |
| Date | 2026-03-30 |
| Status | Production-ready — 100% attack detection, 0% FP, 61 demo investigations loaded |
| Stack | Go API + Python Temporal Worker + React Dashboard + PostgreSQL/pgvector + Redis + Ollama |
| Models | Meta Llama 3.2 3B (fast/param fill) + Meta Llama 3.1 8B (code gen/assess). American only. Zero Chinese dependencies. |
| LLM Host | Ollama on host port 11434. No litellm. Direct httpx POST. |
| Pipeline | V2 5-stage — only 2 of 5 stages call the LLM |
| Templates | 14 active (12 hand-written + 2 auto-promoted via flywheel) |
| Tests | 155 unit + 14 integration + 515-alert corpus |
| Services | 9 core Docker containers + optional profiles |
| Dashboard | React 19 + TypeScript + Vite 7 + Tailwind 4, 17 pages, SOC War Room design |
| Database | PostgreSQL 16 + pgvector, 83 tables, 58 migrations |
| Concurrency | 8 concurrent activities, 16 concurrent workflows (Temporal parallel pool) |

## Credentials

| Resource | Credential |
|----------|------------|
| Admin login | admin@test.local / TestPass2026 (tenant e1c1bc5d) |
| Database | user=zovark, password=hydra_dev_2026, db=zovark |
| Redis | password=hydra-redis-dev-2026 |
| LLM endpoint | `ZOVARK_LLM_ENDPOINT=http://host.docker.internal:11434/v1/chat/completions` |
| LLM key | `ZOVARK_LLM_KEY=sk-zovark-dev-2026` |
| JWT | 30-minute access tokens |

DB and Redis passwords were intentionally not renamed during the rebrand (`hydra_dev_2026`, `hydra-redis-dev-2026`). Use these exact values in all docker/psql/redis-cli commands.

---

## Architecture — V2 Investigation Pipeline

```
SIEM Alert --> Go API (:8090) --> Temporal --> InvestigationWorkflowV2

  Stage 1 INGEST   [NO LLM]  sanitize -> normalize -> batch -> dedup (Redis) -> PII mask -> skill retrieval
  Stage 2 ANALYZE  [LLM opt] Path A: template fast-fill (~350ms, no LLM)
                              Path B: template + LLM param fill (~30s, FAST model)
                              Path C: full LLM code generation (~120s, CODE model)
                              Benign: benign-system-event template (~350ms, no LLM)
  Stage 3 EXECUTE  [NO LLM]  4-layer AST prefilter (allowlist) -> Docker sandbox
                              (network=none, read-only, seccomp, 512MB, 64 PIDs, 120s timeout)
                              Safety wrapper on Path C (guarantees JSON on crash, risk=0 not 50)
  Stage 4 ASSESS   [LLM opt] Verdict derivation -> IOC extraction -> evidence_refs -> MITRE mapping
                              Signal boost (8 regex patterns) -> risk floor -> learning gate
                              Plain-English summary -> validation override
                              Benign: risk<=35 -> benign unconditionally
  Stage 5 STORE    [NO LLM]  agent_tasks + investigations + audit_events + investigation_memory
                              path_taken + generated_code stored for flywheel

  --> Structured Verdict: findings, IOCs (with evidence_refs), risk_score, verdict, MITRE ATT&CK, summary
```

### Four Code Paths

| Path | Trigger | Speed | LLM Model | Example |
|------|---------|-------|-----------|---------|
| A (template) | task_type matches skill template | ~350ms | None | brute_force, phishing, ransomware |
| B (template + LLM fill) | template + LLM param extraction | ~30s | FAST (llama3.2:3b) | lateral_movement with enriched SIEM |
| C (full LLM gen) | no matching template | ~120s | CODE (llama3.1:8b) | kerberoasting, golden_ticket, defense_evasion |
| Benign | task_type matches benign-system-event | ~350ms | None | password_change, windows_update, health_check |

### Two-Model Routing

Zovark routes LLM calls to different models based on task complexity:

| Pipeline Stage | Model | Env Var | Why |
|---------------|-------|---------|-----|
| Path B (param fill) | llama3.2:3b | `ZOVARK_MODEL_FAST` | Simple JSON field extraction, speed matters |
| Path C (code gen) | llama3.1:8b | `ZOVARK_MODEL_CODE` | Needs code generation quality |
| Assess (verdict) | llama3.1:8b | `ZOVARK_MODEL_CODE` | Needs extraction quality for IOCs/verdicts |
| Path A (template) | None | -- | Template fast-fill, no LLM needed |
| Benign routing | None | -- | Inverted logic, no LLM needed |

Why American models: Target customers (US defense/CMMC, healthcare/HIPAA) reject Chinese model provenance. Previously used Qwen 2.5 14B (Alibaba). Switched to Meta Llama (American, open weights). All Qwen/Alibaba references removed from code, config, and docs.

Dual-endpoint opt-in via `ZOVARK_LLM_ENDPOINT_FAST` and `ZOVARK_LLM_ENDPOINT_CODE`. If only `ZOVARK_LLM_ENDPOINT` is set, both use the same instance with model swap on demand.

### Benign Routing (Inverted Logic)

`worker/stages/ingest.py` has `ATTACK_INDICATORS` list. If task_type/rule_name/title do NOT match any attack indicator, the alert routes to the `benign-system-event` skill template (31 benign task types registered). Novel benign alerts default to benign, not to expensive LLM Path C.

### Key Calibration Logic

- **Assess prompt anchors** (`dpo/prompts_v2.py`): Concrete risk reference points for Llama models (e.g., brute force 500+ attempts = risk 95-100, phishing URL = risk 80-90)
- **Attack signal boost** (`assess.py`): 8 regex patterns (SQLi, XSS, path traversal, etc.) add risk when found in SIEM data
- **Template attack risk floor** (`assess.py`): If task_type matches known attack indicator AND risk is underscored, boost to threshold. Prevents LLM under-scoring.
- **Learning gate** (`assess.py`): Path C results are flagged `needs_analyst_review` for human feedback loop
- **Validation override** (`assess.py`): If output validator flags `needs_manual_review` but risk >= 70, override to `true_positive`
- **Prose stripping** (`analyze.py` `_scrub_code()`): Llama 8B wraps code in prose ("Here is the Python code..."). Scrubber detects first Python-like line and strips everything before/after.
- **Plain-English summary** (`assess.py`): Human-readable investigation summary generated alongside structured verdict

---

## Key Files

### Worker Pipeline (Python)

| File | Purpose |
|------|---------|
| `worker/stages/ingest.py` | Stage 1: sanitize, normalize, batch, dedup, PII mask, skill retrieval |
| `worker/stages/analyze.py` | Stage 2: path decision (A/B/C/benign), code gen, code cache, template-only mode, circuit breaker |
| `worker/stages/execute.py` | Stage 3: 4-layer AST prefilter (allowlist) + Docker sandbox execution |
| `worker/stages/assess.py` | Stage 4: verdict, IOC extraction, signal boost, learning gate, plain-English summary |
| `worker/stages/store.py` | Stage 5: DB writes with synchronous_commit, stores path_taken + generated_code |
| `worker/stages/llm_gateway.py` | Dual-endpoint routing (MODEL_FAST/MODEL_CODE), audit logging |
| `worker/stages/investigation_workflow.py` | InvestigationWorkflowV2 — 5-stage Temporal orchestrator |
| `worker/stages/input_sanitizer.py` | 12 injection patterns, field truncation, entropy analysis |
| `worker/stages/normalizer.py` | 70+ field mappings (Splunk/Elastic/firewall/legacy) |
| `worker/stages/smart_batcher.py` | Redis-backed, severity-aware batching windows |
| `worker/stages/circuit_breaker.py` | GREEN/YELLOW/RED states, hysteresis recovery |
| `worker/stages/code_cache.py` | Structural key hashing, 24h TTL, Redis-backed |
| `worker/stages/template_promoter.py` | Templatize, validate, promote Path C code to agent_skills |
| `worker/stages/output_validator.py` | Schema validation, IOC normalization |
| `worker/stages/mitre_mapping.py` | MITRE ATT&CK technique mapping |

### Go API

| File | Purpose |
|------|---------|
| `api/main.go` | Gin router, 90+ registered routes |
| `api/auth.go` | JWT (30min), OIDC/SSO, TOTP 2FA |
| `api/task_handlers.go` | Task CRUD, verdict/risk/path in list response |
| `api/promotion_handlers.go` | promotion-queue, analyst-feedback, auto-templates, dashboard-stats |
| `api/siem_ingest.go` | Splunk HEC + Elastic SIEM webhook ingest |
| `api/cipher_audit_handlers.go` | 5 cipher audit API endpoints |

### Other Key Files

| File | Purpose |
|------|---------|
| `agent/healer.py` | Fleet agent: self-healer + Sneakernet UI + AI crash diagnosis |
| `dpo/prompts_v2.py` | Full prompt library: system, task, tools, RAG, retry, scoring anchors (~900 LOC) |

---

## Investigation Code Cache

Redis-based cache for Path C generated code. Repeat alert patterns skip LLM entirely.

- **Key:** hash(task_type + rule_name + sorted SIEM field names) -- structural, not value-based
- **TTL:** 24 hours (configurable via `ZOVARK_CODE_CACHE_TTL`)
- **Flush after prompt updates:** `scripts/flush_code_cache.sh`
- **Implementation:** `worker/stages/code_cache.py`, integrated in `analyze.py`

---

## AST Prefilter Allowlist

Stage 3 uses a 4-layer AST prefilter. Only these standard library modules are permitted in generated investigation code:

`json`, `re`, `datetime`, `collections`, `math`, `hashlib`, `ipaddress`, `base64`, `urllib.parse`, `csv`, `statistics`, `string`, `copy`, `itertools`, `functools`, `typing`

Everything else (os, sys, subprocess, socket, eval, exec, etc.) is blocked before sandbox execution.

---

## Database

| Field | Value |
|-------|-------|
| Engine | PostgreSQL 16 + pgvector |
| Credentials | user=zovark, password=hydra_dev_2026, db=zovark |
| Tables | 83 |
| Migrations | 58 files in `migrations/` |
| Connection pooling | PgBouncer (400 client / 25 server) |
| Key tables | agent_tasks, investigations, agent_skills (14 templates), llm_audit_log, cipher_audit_events, audit_events (partitioned), entities, entity_edges, detection_rules, response_playbooks, cross_tenant_entities, investigation_memory (SINGULAR name) |

Apply migrations: `docker compose exec -T postgres psql -U zovark -d zovark < migrations/NNN_name.sql`

---

## Skill Templates (14 Active)

12 hand-written templates + 2 auto-promoted via flywheel, stored in `agent_skills.code_template`:

| Slug | Types | Purpose |
|------|-------|---------|
| brute-force-investigation | 4 | Auth failure counting, credential stuffing, protocol detection |
| phishing-investigation | 3 | URL analysis, email headers, typosquatting, attachments |
| ransomware-triage | 3 | Shadow copy deletion, mass encryption, ransom notes |
| data-exfiltration-detection | 9 | Transfer volume, cloud storage, encoding, off-hours |
| privilege-escalation-hunt | 1 | Sudo/su, UAC bypass, SUID, token manipulation |
| c2-communication-hunt | 1 | Beacon intervals, DGA entropy, C2 signatures |
| lateral-movement-detection | 1 | PsExec/WMI/WinRM, pass-the-hash, admin shares |
| insider-threat-detection | 1 | Off-hours, bulk access, data staging, HR context |
| network-beaconing | 4 | Timestamp analysis, DNS anomalies, fixed payloads |
| cloud-infrastructure-attack | 1 | IAM changes, CloudTrail tampering, resource spikes |
| supply-chain-compromise | 1 | Hash mismatches, typosquatted packages, CI/CD mods |
| **benign-system-event** | **31** | Returns risk=15, verdict=benign for routine system operations |
| auto-credential_access-d58e8e | -- | Auto-promoted via flywheel (credential access patterns) |
| auto-golden_ticket-590d86 | -- | Auto-promoted via flywheel (golden ticket detection) |

---

## Docker Services

### Core (9 services -- `docker compose up -d`)

| Service | Image | Port | Container |
|---------|-------|------|-----------|
| postgres | pgvector/pgvector:pg16 | 5432 | zovark-postgres |
| redis | redis:7-alpine | 6379 | zovark-redis |
| pgbouncer | edoburu/pgbouncer | 6432 | zovark-pgbouncer |
| temporal | temporalio/auto-setup:1.24.2 | 7233 | zovark-temporal |
| api | Custom Go build | 8090 | zovark-api |
| worker | Custom Python build | -- | hydra-mvp-worker-1 |
| dashboard | Custom React (nginx) | 3000 | zovark-dashboard |
| healer | Python (agent/healer.py) | 8081 | zovark-healer |
| squid-proxy | ubuntu/squid | 3128 | zovark-egress-proxy |

### LLM (runs on HOST, not Docker)

- Ollama on port 11434 with `llama3.1:8b` (code/assess) + `llama3.2:3b` (fast param fill)
- Worker connects via `http://host.docker.internal:11434/v1/chat/completions`
- No litellm -- removed due to supply chain risk (PyPI compromise). Direct httpx POST to Ollama.

### Optional Profiles

| Profile | Services |
|---------|----------|
| siem-lab | Elasticsearch, Kibana, Filebeat, Juice-Shop, nginx-proxy |
| monitoring | Prometheus, Grafana, postgres-exporter, redis-exporter |
| debug | temporal-ui |
| storage | MinIO |
| tls | Caddy |
| airgap-ollama | Ollama in Docker (when not on host) |

---

## Fleet Agent (agent/healer.py)

Self-healing fleet agent running on port 8081:

- **Sneakernet UI:** Embedded web interface for air-gapped deployments
- **AI crash diagnosis:** Uses 3B model to analyze container failures and suggest fixes
- **3-level escalation:** auto-restart -> AI diagnosis -> operator alert
- **Daily reports:** Automated health summaries
- **Container:** zovark-healer

---

## Dashboard

| Field | Value |
|-------|-------|
| Stack | React 19 + TypeScript + Vite 7 + Tailwind 4 |
| Pages | 17 |
| Components | 16 |
| Design | SOC War Room -- #060A14 background, #00FF88 green accents, JetBrains Mono font |
| Port | 3000 (Docker/nginx), 5173 (dev) |

---

## Environment Variables

All variables have sensible defaults. Key configuration:

### Mode and Models

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZOVARK_MODE` | `full` | `full` or `templates-only` (skip LLM entirely) |
| `ZOVARK_MODEL_FAST` | `llama3.2:3b` | Fast model for Path B param fill |
| `ZOVARK_MODEL_CODE` | `llama3.1:8b` | Code model for Path C gen + Assess |
| `ZOVARK_FAST_FILL` | `false` | Enable template fast-fill mode |

### LLM Endpoints

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZOVARK_LLM_ENDPOINT` | `http://host.docker.internal:11434/v1/chat/completions` | Single Ollama endpoint (both models) |
| `ZOVARK_LLM_ENDPOINT_FAST` | -- | Dedicated endpoint for 3B model (dual-instance) |
| `ZOVARK_LLM_ENDPOINT_CODE` | -- | Dedicated endpoint for 8B model (dual-instance) |
| `ZOVARK_LLM_KEY` | `sk-zovark-dev-2026` | API key for LLM endpoint |

### Timeouts and Thresholds

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZOVARK_ASSESS_TIMEOUT` | `45` | Seconds before assess stage times out |
| `ZOVARK_HUMAN_REVIEW_THRESHOLD` | `60` | Risk score threshold for human review flag |
| `ZOVARK_CB_YELLOW` | `50` | Circuit breaker yellow threshold |
| `ZOVARK_CB_RED` | `100` | Circuit breaker red threshold |
| `ZOVARK_CB_RECOVERY` | `25` | Circuit breaker recovery threshold |

### Batching and Caching

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZOVARK_BATCH_WINDOW_SECONDS` | `60` | Smart batcher window |
| `ZOVARK_BATCH_MAX_SIZE` | `500` | Max alerts per batch |
| `ZOVARK_CODE_CACHE_TTL` | `86400` | Code cache TTL in seconds (24h) |
| `DEDUP_ENABLED` | `true` | Redis deduplication |

### Infrastructure

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | -- | PostgreSQL connection string |
| `REDIS_URL` | -- | Redis connection string |
| `REDIS_PASSWORD` | `hydra-redis-dev-2026` | Redis password |
| `JWT_SECRET` | -- | JWT signing secret |
| `TEMPORAL_ADDRESS` | -- | Temporal server address |

---

## Security Implementation

| Layer | What | Status |
|-------|------|--------|
| Input Sanitization | 12 injection patterns detected/stripped, field truncation at 10K chars, Shannon entropy analysis | IMPLEMENTED |
| AST Prefilter | 4-layer allowlist -- only 16 safe stdlib modules permitted | IMPLEMENTED |
| Docker Sandbox | network=none, read-only, cap-drop ALL, 512MB, 64 PIDs, seccomp, 120s timeout | IMPLEMENTED |
| Safety Wrapper | Path C code wrapped in try/except, risk=0 on crash (not 50) | IMPLEMENTED |
| Code Scrubbing | Strips markdown fences, LLM tokens, prose wrapping from generated code | IMPLEMENTED |
| JWT Auth | 30-minute access tokens | IMPLEMENTED |
| RBAC | admin/analyst/viewer/api_key enforced in middleware | IMPLEMENTED |
| OIDC/SSO | Azure AD, Okta (api/auth.go) | IMPLEMENTED |
| TOTP 2FA | RFC 6238 | IMPLEMENTED |
| Audit Trail | audit_events table, monthly partitions | IMPLEMENTED |
| Synchronous Commit | Critical writes use `SET LOCAL synchronous_commit = on` | IMPLEMENTED |
| Evidence Citations | Every IOC has evidence_refs linking to source log line | IMPLEMENTED |
| Zero Hallucination | Prompt rules forbid inventing IOCs not in log data | IMPLEMENTED |
| Error Handling | `respondInternalError()` -- never expose Go errors to clients | IMPLEMENTED |
| Circuit Breaker | GREEN/YELLOW/RED states prevent cascading LLM failures | IMPLEMENTED |
| Learning Gate | Path C results flagged needs_analyst_review for human feedback | IMPLEMENTED |

---

## API Routes (90+)

Key route groups on the Go API (port 8090):

| Group | Examples |
|-------|---------|
| Auth | login, register, refresh, OIDC callback, TOTP setup/verify |
| Tasks | CRUD, list with verdict/risk/path, batch submit |
| Approvals | approve/reject investigation actions |
| SIEM Ingest | POST /api/v1/ingest/splunk, POST /api/v1/ingest/elastic |
| Playbooks | SOAR response playbooks, approval gates |
| Skills | agent_skills CRUD, template management |
| Webhooks | external notification endpoints |
| Analytics | investigation stats, trend data |
| Feedback | analyst feedback on verdicts |
| Intelligence | cross-tenant entity resolution |
| Detection | Sigma rule management |
| Response | response playbook execution |
| Cipher Audit | 5 endpoints, NIST SP 800-57 compliance |
| Promotion Queue | promotion-queue, analyst-feedback, auto-templates, dashboard-stats |
| Shadow | shadow mode testing endpoints |
| Automation | automated workflow triggers |
| Quotas | tenant resource quotas |
| Metrics | Prometheus /metrics endpoint |
| Integrations | external system connections |
| Health | GET /health |

---

## Tests

| Category | Count | Details |
|----------|-------|---------|
| Sanitizer unit tests | 44 | Input sanitization patterns |
| Prefilter unit tests | 78 | AST allowlist enforcement |
| Normalizer unit tests | 19 | Field mapping validation |
| Misc unit tests | 14 | Other unit tests |
| Integration tests | 14 | End-to-end pipeline validation |
| Alert corpus | 515 | Full alert corpus for regression testing |
| **Total** | **155 unit + 14 integration + 515-alert corpus** | |

---

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/deploy.sh` | Production deployment |
| `scripts/hardware_check.sh` | Verify hardware requirements |
| `scripts/validate_update.sh` | Full validation after updates |
| `scripts/validate_update_quick.sh` | Quick validation after updates |
| `scripts/build_bundle.sh` | Build air-gap deployment bundle |
| `scripts/flush_code_cache.sh` | Clear Redis code cache (run after prompt changes) |
| `scripts/run_ci_tests.sh` | Run CI test suite |

---

## Benchmarks

| Benchmark | Result |
|-----------|--------|
| 1000-alert corpus | 983/1000 completed, 100% attack detection, 0 false negatives |
| Juice Shop (100 real-traffic) | 99/100 accuracy (70/70 attacks, 29/30 benign) |
| 200-benign calibration | 200/200 benign, 0% false positive rate |
| Path C novel attacks (10 types) | 10/10 correct (kerberoasting, golden_ticket, LOLBins, etc.) |
| Template fast-fill throughput | ~350ms per investigation |

---

## Coding Conventions

- **Tenant isolation:** Every DB query MUST include `tenant_id` in WHERE clause
- **Error handling (Go):** Use `respondInternalError()` -- never expose `err.Error()` to clients
- **LLM calls:** Always through `worker/stages/llm_gateway.py` via `ZOVARK_LLM_ENDPOINT`
- **No litellm:** Direct httpx POST to Ollama. Zero AI proxy libraries.
- **Model routing:** Use `MODEL_FAST` for param fill, `MODEL_CODE` for code gen + assess
- **Sandbox code:** Must pass AST prefilter allowlist -- only the 16 approved stdlib modules
- **Skill templates:** Stored in `agent_skills.code_template`, use `{{siem_event_json}}` placeholder
- **New activities:** Add to `worker/stages/*.py`, register in `worker/stages/register.py`
- **Migrations:** Sequential in `migrations/`, apply via `docker compose exec -T postgres psql -U zovark -d zovark < migrations/NNN_name.sql`
- **After Python changes:** `docker compose build worker && docker compose up -d worker`
- **After Go changes:** `docker compose build api && docker compose up -d api`
- **Before benchmarks:** Terminate stale Temporal workflows first
- **investigation_memory table:** Name is SINGULAR. Plural reference silently fails.

---

## How to Run

```bash
# Start all services (9 core containers)
docker compose up -d

# Start Ollama on host (if not already running)
ollama serve
# Ensure both models are pulled:
ollama pull llama3.1:8b
ollama pull llama3.2:3b

# Verify health
curl -s http://localhost:8090/health

# Login (30-minute JWT)
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' \
  | sed 's/.*"token":"\([^"]*\)".*/\1/')

# Submit investigation
curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"brute_force","input":{"prompt":"SSH brute force","severity":"high","siem_event":{"title":"SSH BF","source_ip":"185.220.101.45","username":"root","rule_name":"BruteForce","raw_log":"500 failed for root from 185.220.101.45"}}}'

# Poll for result
curl -s http://localhost:8090/api/v1/tasks/<TASK_ID> -H "Authorization: Bearer $TOKEN"
```

---

## Key Docs

| Doc | Path |
|-----|------|
| Implementation Audit | `docs/ZOVARK_IMPLEMENTATION_AUDIT.md` |
| Architecture | `docs/ARCHITECTURE.md` |
| API Spec (OpenAPI) | `docs/openapi.yaml` |
| Whitepaper | `docs/WHITEPAPER.md` |
| Sandbox Security | `docs/SANDBOX_SECURITY.md` |
| SIEM Integration | `docs/SIEM_INTEGRATION.md` |
| Juice Shop Benchmark | `docs/JUICE_SHOP_BENCHMARK.md` |
| Model Deployment | `docs/MODEL_DEPLOYMENT.md` |
| Hardware Requirements | `docs/HARDWARE_REQUIREMENTS.md` |
| BlackHat CFP | `docs/outreach/blackhat_cfp.md` |
| CISO Brief | `marketing/outreach/ZOVARK_CISO_Brief.pdf` |

---

## Sprints Shipped

| Sprint | What |
|--------|------|
| 1E | Production hardening -- sync commit, SCRAM auth, audit events, FK constraints |
| 1F | Observability -- Prometheus + Grafana monitoring stack |
| 1H | Bootstrap pipeline -- MITRE ATT&CK + CISA KEV ingestion |
| 1I | Model tiering -- prompt versioning + performance tracking |
| 1J | Autoscaling -- KEDA ScaledObject + queue depth exporter |
| 1K | Cross-tenant entity resolution with privacy-preserving hashes |
| 2A | Self-generating detection engine -- Sigma rule generator |
| 2B | SOAR response playbooks -- 5 defaults, approval gates, rollback |
| 2C | Cipher audit skill -- NIST SP 800-57 deterministic + LLM narration |
| 2D | Two-model routing -- American models only (Meta Llama), Qwen removed |
| 2E | Dual Ollama routing -- CPU (3B) + GPU (8B), zero swap latency |
| 2F | Security hardening -- input sanitizer, allowlist AST prefilter |
| 2G | Code cache -- Redis-based, repeat patterns skip LLM |

---

## Known Issues

1. **Healer HTTP thread** — Blocks during health check cycles on Windows Docker Desktop (GIL + subprocess contention). Works on Linux.
2. **DB/Redis passwords** — Still `hydra_dev_2026` / `hydra-redis-dev-2026`. Intentional, non-breaking.
3. **DPO pipeline** — Training data exists in `dpo/` but no production model trained.
4. **SIEM lab Filebeat** — Needs polling mode + bind mount on Windows Docker.

---

## What Was Built This Session (March 29-30, 2026)

From commit 8507c11 to f0f8b2f — 27 commits in one session:

1. **Complete HYDRA→Zovark rebrand** — 100+ files, all code/config/docs/monitoring/MCP server
2. **Two-model routing** — Meta Llama 3.2 3B + 3.1 8B, zero Chinese dependencies
3. **3 Llama calibration fixes** — prose stripping, risk anchors, verdict override
4. **Dual Ollama routing** — CPU (3B) + GPU (8B) endpoints, zero swap latency
5. **Security hardening** — input sanitizer (12 patterns), allowlist AST prefilter, smart_truncate
6. **Redis code cache** — repeat patterns skip LLM (24h TTL)
7. **CI/CD layer** — mock Ollama + 14 integration tests + GitHub Actions
8. **SIEM lab** — Juice Shop → Elastic → Poller → Bridge → Zovark (end-to-end verified)
9. **Template promotion flywheel** — Path C → analyst review → auto-promote → Path A (428ms)
10. **SOC War Room dashboard** — new design system, 2 new pages, 5 new components, Zovark logo
11. **Zovark Core normalizer** — 70+ field mappings, 4 SIEM formats
12. **TaskList data fix** — verdict/risk/path columns show real data from API
13. **JWT extended** to 30 minutes
14. **Template-only mode** — `ZOVARK_MODE=templates-only` for $40K Essentials tier
15. **Smart batching** — 60% alert reduction, severity-aware windows
16. **Circuit breaker** — GREEN/YELLOW/RED auto-degradation during storms
17. **Plain-English summaries** — deterministic bullet-point for L1 analysts
18. **Hardware check script** — validates deployment hardware, recommends tier
19. **DMZ deployment script** — one-command `deploy.sh` with SIEM webhook config
20. **VM appliance template** — Packer for Ubuntu 24.04 OVA/QCOW2
21. **Fleet Agent self-healer** — AI crash diagnosis, 3-level escalation, Sneakernet UI
22. **Crypto bundle system** — Ed25519 signed .zvk update packages
23. **Parallel worker pool** — 8 concurrent activities via Temporal (was 1)
24. **smart_truncate** — fixes 10K padding truncation vulnerability
25. **61 demo investigations** loaded (32 benign + 29 attacks, zero FP/FN)

## Pending Work

1. **A100 benchmark** — Rerun with parallel workers on fast hardware
2. **Healthcare template pack** — 30 industry-specific templates
3. **SIEM verdict push-back** — POST verdicts back to Splunk/Elastic
4. **Blue/green deployment** — Zero-downtime updates with auto-rollback
5. **Community template sync** — Network effect moat across customers
6. **Public self-serve demo** — Standalone browser demo for CISO outreach
7. **Design partner outreach** — Target healthcare MSSPs first
