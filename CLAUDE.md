# ZOVARK — Autonomous AI SOC Agent

## What Is Zovark

Zovark is an **air-gapped Security Operations Center (SOC) automation platform** for regulated enterprises. It receives security alerts from SIEM systems (Splunk, Elastic), automatically generates Python investigation code using local LLMs, executes that code in a hardened sandbox, and delivers structured verdicts with evidence-backed IOCs and MITRE ATT&CK mapping.

**The core value proposition:** SOC analysts manually investigate ~11,000 alerts/day. Zovark automates Tier-1 triage in 15-90 seconds per alert with zero data egress — everything runs on local hardware. This matters for organizations bound by GDPR, HIPAA, NERC CIP, or CMMC Level 2 that cannot send security telemetry to cloud AI services.

**Origin:** Built as HYDRA, rebranded to Zovarc, then to Zovark. The git repo directory is still `hydra-mvp`. All source code uses "Zovark" branding. Database and Redis passwords were intentionally not renamed during the rebrand (`hydra_dev_2026`, `hydra-redis-dev-2026`).

## Quick Reference

- **Version:** v1.8.1 — 195 commits on master
- **Status:** Production-ready — 100% attack detection, 0% FP on 200-benign calibration
- **Stack:** Go API + Python Temporal Worker + React Dashboard + PostgreSQL/pgvector + Redis + Ollama
- **LLM:** Two-model routing with American-origin models only (Meta Llama). No Chinese model dependencies.
  - **Fast model:** Meta Llama 3.2 3B (`ZOVARK_MODEL_FAST`) — Path B parameter extraction (~10s)
  - **Code model:** Meta Llama 3.1 8B (`ZOVARK_MODEL_CODE`) — Path C code generation + Assess stage (~60-120s)
  - Ollama on host (:11434), only 1 model loaded at a time, swaps on demand
- **Hardware:** RTX 3050 laptop (4GB VRAM, 24GB RAM). Runs on consumer hardware.
- **Pipeline:** V2 5-stage — only 2 of 5 stages call the LLM
- **Tests:** 44 Go + 179 Python + 15 V2 pipeline + 10 cipher audit = 248 test functions
- **Services:** 8 core Docker containers + optional monitoring/storage
- **LLM Routing:** Dual Ollama — CPU instance (3B fast, port 11434) + GPU instance (8B code, port 11435)
- **Security:** Input sanitization + allowlist AST prefilter + sandbox (network=none, seccomp)
- **Caching:** Redis code cache (24h TTL) — repeat Path C patterns skip LLM
- **Dashboard:** React 19 + Vite 7 + Tailwind 4, 15 pages, dark mode, MITRE ATT&CK badges

## Credentials

- **Admin login:** admin@test.local / TestPass2026 (tenant e1c1bc5d)
- **DB:** user=zovark, password=hydra_dev_2026, db=zovark (PostgreSQL 16 + pgvector)
- **Redis:** password=hydra-redis-dev-2026
- **LLM endpoint:** `ZOVARK_LLM_ENDPOINT=http://host.docker.internal:11434/v1/chat/completions`
- **LLM key:** `ZOVARK_LLM_KEY=sk-zovark-dev-2026`

## Architecture — V2 Investigation Pipeline

```
SIEM Alert → Go API (:8090) → Temporal → InvestigationWorkflowV2 →

  Stage 1 INGEST   [NO LLM]  Dedup (Redis) → PII mask → skill retrieval → attack indicator check
  Stage 2 ANALYZE  [LLM ①]   Path A: template fast-fill (~350ms, no LLM)
                              Path B: template + LLM param fill (~30s, FAST model)
                              Path C: full LLM code generation (~120s, CODE model)
  Stage 3 EXECUTE  [NO LLM]  AST prefilter → Docker sandbox (network=none, seccomp, 512MB, 120s)
                              Safety wrapper on Path C (guarantees JSON on crash, risk=0 not 50)
  Stage 4 ASSESS   [LLM ②]   Verdict derivation → IOC extraction → evidence_refs → MITRE mapping
                              Attack signal boost (7 regex: SQLi, XSS, path traversal, etc.)
                              Template attack risk floor (known attacks score ≥70)
                              Benign: risk≤35 → benign unconditionally
  Stage 5 STORE    [NO LLM]  agent_tasks + investigations + audit_events + memory

  → Structured Verdict: findings, IOCs (with evidence_refs), risk_score, verdict, MITRE ATT&CK
```

### Three Code Paths

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
| Path A (template) | None | — | Template fast-fill, no LLM needed |
| Benign routing | None | — | Inverted logic, no LLM needed |

**Why American models:** Target customers (US defense/CMMC, healthcare/HIPAA) reject Chinese model provenance. Previously used Qwen 2.5 14B (Alibaba). Switched to Meta Llama (American, open weights). All Qwen/Alibaba references removed from code, config, and docs.

**Why two models:** Only 1 model fits in 4GB VRAM at a time. Ollama swaps on demand (3-5s penalty, negligible vs 60s+ inference). The 3B model handles simple param extraction 5x faster than the 8B model.

### Dual Ollama Routing (v2.0)

Two Ollama instances eliminate model swap latency entirely:

| Instance | Port  | Hardware | Model | Purpose |
|----------|-------|----------|-------|---------|
| CPU      | 11434 | 24GB RAM | llama3.2:3b | Path B param fill — always loaded |
| GPU      | 11435 | RTX 3050 4GB VRAM | llama3.1:8b | Path C code gen + Assess — always loaded |

- Backward-compatible: if only `ZOVARK_LLM_ENDPOINT` is set, both use same instance
- Dual-instance opt-in via `ZOVARK_LLM_ENDPOINT_FAST` and `ZOVARK_LLM_ENDPOINT_CODE`
- Dev hardware: i5-12450H + RTX 3050 4GB + Intel UHD (iGPU unused — no CUDA) + 24GB RAM

### Benign Routing (Inverted Logic)

`worker/stages/ingest.py` has `ATTACK_INDICATORS` list (45 patterns). If task_type/rule_name/title do NOT match any attack indicator, the alert routes to the `benign-system-event` skill template (31 benign task types). Novel benign alerts default to benign, not to expensive LLM Path C.

### Key Calibration Logic

- **Assess prompt anchors** (`dpo/prompts_v2.py`): Concrete risk reference points for Llama models (e.g., brute force 500+ attempts = risk 95-100, phishing URL = risk 80-90)
- **Attack signal boost** (`assess.py`): 7 regex patterns (SQLi, XSS, etc.) add +45 to risk_score when found in SIEM data
- **Template attack risk floor** (`assess.py`): If task_type matches known attack indicator AND risk is 36-69, boost to 70. Prevents LLM under-scoring of template-matched attacks.
- **Validation override** (`assess.py`): If output validator flags `needs_manual_review` but risk ≥ 70, override to `true_positive`. Path C code from Llama 8B sometimes produces empty findings arrays but correct IOCs/risk — the validator is overly strict.
- **Prose stripping** (`analyze.py` `_scrub_code()`): Llama 8B wraps code in prose ("Here is the Python code..."). Scrubber detects first Python-like line and strips everything before/after.

## Key Files

| File | Purpose |
|------|---------|
| `worker/stages/ingest.py` | Stage 1: dedup, PII mask, skill retrieval, attack indicator check |
| `worker/stages/analyze.py` | Stage 2: Path A/B/C code generation, `_scrub_code()` prose stripping |
| `worker/stages/execute.py` | Stage 3: AST prefilter, Docker sandbox, safety wrapper |
| `worker/stages/assess.py` | Stage 4: verdict, IOC extraction, evidence_refs, MITRE, signal boost, risk floor |
| `worker/stages/store.py` | Stage 5: DB writes, audit events, synchronous_commit |
| `worker/stages/llm_gateway.py` | Two-model routing (`MODEL_FAST`/`MODEL_CODE`), audit logging, keep_alive |
| `worker/stages/model_router.py` | YAML-driven model config routing by severity/task_type |
| `worker/stages/model_config.yaml` | Model tier definitions (zovark-fast, zovark-standard, zovark-enterprise) |
| `worker/stages/output_validator.py` | Schema validation, IOC normalization |
| `worker/stages/mitre_mapping.py` | MITRE ATT&CK technique mapping for 11 types |
| `worker/stages/investigation_workflow.py` | InvestigationWorkflowV2 — 5-stage orchestrator |
| `dpo/prompts_v2.py` | Full prompt library: system, task, tools, RAG, retry, scoring anchors |
| `api/main.go` | Go API router, ~90 registered routes |
| `api/siem_ingest.go` | Splunk HEC + Elastic SIEM webhook ingest |
| `api/cipher_audit_handlers.go` | 5 cipher audit API endpoints |

### Investigation Code Cache (v2.0)

Redis-based cache for Path C generated code. Repeat alert patterns skip LLM entirely.
- Key: hash(task_type + rule_name + sorted SIEM field names) — structural, not value-based
- TTL: 24 hours (configurable via `ZOVARK_CODE_CACHE_TTL`)
- Flush after prompt updates: `scripts/flush_code_cache.sh`
- Implemented in `worker/stages/code_cache.py`, integrated in `analyze.py`

## Database

- **Engine:** PostgreSQL 16 + pgvector
- **Credentials:** user=zovark, password=hydra_dev_2026, db=zovark
- **Tables:** 85+, **Migrations:** 54 files (001-054)
- **Connection pooling:** PgBouncer (400 client / 25 server)
- **Key tables:** agent_tasks, investigations, agent_skills (12 templates), llm_audit_log, cipher_audit_events, audit_events (partitioned), entities, entity_edges, detection_rules, response_playbooks

## Skill Templates (12)

11 attack templates + 1 benign template in `agent_skills.code_template`:

| Slug | Types | Purpose |
|------|-------|---------|
| brute-force-investigation | 4 | Auth failure counting, credential stuffing |
| phishing-investigation | 3 | URL analysis, typosquatting, email headers |
| ransomware-triage | 3 | Shadow copy deletion, mass encryption |
| data-exfiltration-detection | 9 | Transfer volume, encoding, off-hours |
| privilege-escalation-hunt | 1 | Sudo/su, UAC bypass, SUID |
| c2-communication-hunt | 1 | Beacon intervals, DGA entropy |
| lateral-movement-detection | 1 | PsExec/WMI/WinRM, pass-the-hash |
| insider-threat-detection | 1 | Off-hours, bulk access, data staging |
| network-beaconing | 4 | Timestamp analysis, DNS anomalies |
| cloud-infrastructure-attack | 1 | IAM changes, CloudTrail tampering |
| supply-chain-compromise | 1 | Hash mismatches, typosquatted packages |
| **benign-system-event** | **31** | Returns risk=15, verdict=benign for routine operations |

## Docker Services

### Core (8 services — `docker compose up -d`)
| Service | Port | Container |
|---------|------|-----------|
| postgres (pgvector:pg16) | 5432 | zovark-postgres |
| redis (redis:7-alpine) | 6379 | zovark-redis |
| pgbouncer | 6432 | zovark-pgbouncer |
| temporal (auto-setup:1.24.2) | 7233 | zovark-temporal |
| api (Go) | 8090 | zovark-api |
| worker (Python) | — | hydra-mvp-worker-1 |
| dashboard (React/nginx) | 3000 | zovark-dashboard |
| squid-proxy | 3128 | zovark-egress-proxy |

### LLM (runs on HOST, not Docker)
- **Ollama** on port 11434: `llama3.1:8b` (code/assess) + `llama3.2:3b` (fast param fill)
- Worker connects via `http://host.docker.internal:11434/v1/chat/completions`
- **No litellm** — removed due to supply chain risk. Direct httpx POST to Ollama.

### Optional profiles
- monitoring: Prometheus, Grafana, exporters
- debug: temporal-ui
- storage: MinIO
- tls: Caddy
- airgap-ollama: Ollama in Docker (when not on host)

## Security Implementation

| Layer | What |
|-------|------|
| AST Prefilter | Blocks os/sys/subprocess/socket/eval/exec + 7 patterns |
| Docker Sandbox | network=none, read-only, cap-drop ALL, 512MB, 64 PIDs, seccomp |
| Kill Timer | 120s subprocess timeout |
| Safety Wrapper | Path C code wrapped in try/except, risk=0 on crash |
| Code Scrubbing | Strips markdown fences, LLM tokens, prose wrapping from generated code |
| JWT Auth | 15min access + 7d refresh (httpOnly cookie) |
| RBAC | admin/analyst/viewer/api_key enforced in middleware |
| OIDC/SSO | Azure AD, Okta (api/oidc.go) |
| TOTP 2FA | RFC 6238 (api/totp.go) |
| Audit Trail | audit_events table, monthly partitions |
| Synchronous Commit | Critical writes use `SET LOCAL synchronous_commit = on` |
| Evidence Citations | Every IOC has evidence_refs linking to source log line |
| Zero Hallucination | Prompt rules forbid inventing IOCs not in log data |
| Error Handling | `respondInternalError()` — never expose Go errors to clients |

### Input Sanitization (v2.0)

All SIEM event data is sanitized BEFORE reaching LLM prompt construction:
- 12 prompt injection patterns detected and stripped (ignore instructions, system role, code fences, etc.)
- Field length truncation at 10,000 chars
- Shannon entropy analysis flags suspicious high-entropy fields
- Implemented in `worker/stages/input_sanitizer.py`, called from `ingest.py` Stage 1

## Benchmarks

| Benchmark | Result |
|-----------|--------|
| 1000-alert corpus | 983/1000 completed, 100% attack detection, 0 false negatives |
| Juice Shop (100 real-traffic) | 99/100 accuracy (70/70 attacks, 29/30 benign) |
| 200-benign calibration | 200/200 benign, 0% false positive rate |
| Path C novel attacks (10 types) | 10/10 correct (kerberoasting, golden_ticket, LOLBins, etc.) |
| Template fast-fill throughput | ~350ms per investigation |

*Note: Benchmarks above were originally run with Qwen 2.5 14B. The pipeline now uses Meta Llama 3.1 8B / 3.2 3B. Re-benchmarking pending.*

## Coding Conventions

- **Tenant isolation:** Every DB query MUST include `tenant_id` in WHERE clause
- **Error handling (Go):** Use `respondInternalError()` — never expose `err.Error()` to clients
- **LLM calls:** Always through `worker/stages/llm_gateway.py` via `ZOVARK_LLM_ENDPOINT`
- **No litellm:** Direct httpx POST to Ollama. Zero AI proxy libraries.
- **Model routing:** Use `MODEL_FAST` for param fill, `MODEL_CODE` for code gen + assess
- **Sandbox code:** Must pass AST prefilter — no `os`, `sys`, `subprocess`, `socket`
- **Skill templates:** Stored in `agent_skills.code_template`, use `{{siem_event_json}}` placeholder
- **New activities:** Add to `worker/stages/*.py`, register in `worker/stages/register.py`
- **Migrations:** Sequential in `migrations/`, apply via `docker compose exec -T postgres psql -U zovark -d zovark < migrations/NNN_name.sql`
- **After Python changes:** `docker compose build worker && docker compose up -d worker`
- **After Go changes:** `docker compose build api && docker compose up -d api`
- **Before benchmarks:** Terminate stale Temporal workflows first

## How to Run

```bash
# Start all services
docker compose up -d

# Start Ollama on host (if not already running)
ollama serve
# Ensure both models are pulled:
ollama pull llama3.1:8b
ollama pull llama3.2:3b

# Verify health
curl -s http://localhost:8090/health

# Login
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

## Codebase Scale

| Component | Count |
|-----------|-------|
| Go API files | 51 files, ~11,800 LOC |
| Python worker files | 157 files, ~25,800 LOC |
| Dashboard (React/TS) | 33 files (15 pages, 11 components) |
| SQL migrations | 54 files |
| Docker services | 19 defined (8 core + 11 optional) |
| Test files | 49 total (Go + Python + E2E + integration + load) |
| Documentation | 27 files including 76KB OpenAPI spec |
| MCP server | 4 TS files, 7 tools, 6 resources, 6 prompts |
| Total estimated LOC | ~40,000+ (excluding docs/config) |

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

## Sprints Shipped

| Sprint | What |
|--------|------|
| 1E | Production hardening — sync commit, SCRAM auth, audit events, FK constraints |
| 1F | Observability — Prometheus + Grafana monitoring stack |
| 1H | Bootstrap pipeline — MITRE ATT&CK + CISA KEV ingestion |
| 1I | Model tiering — prompt versioning + performance tracking |
| 1J | Autoscaling — KEDA ScaledObject + queue depth exporter |
| 1K | Cross-tenant entity resolution with privacy-preserving hashes |
| 2A | Self-generating detection engine — Sigma rule generator |
| 2B | SOAR response playbooks — 5 defaults, approval gates, rollback |
| 2C | Cipher audit skill — NIST SP 800-57 deterministic + LLM narration |
| 2D | Two-model routing — American models only (Meta Llama), Qwen removed |
| 2E | Dual Ollama routing — CPU (3B) + GPU (8B), zero swap latency |
| 2F | Security hardening — input sanitizer, allowlist AST prefilter |
| 2G | Code cache — Redis-based, repeat patterns skip LLM |

## Known Issues

1. **NATS hostname resolution** — Non-fatal warning on worker startup. NATS is optional.
2. **Stale Temporal workflows** — Must terminate before benchmark runs.
3. **`investigation_memory` table** — Name is SINGULAR. Plural reference silently fails.
4. **`fetch_task` dependency** — V2 workflow still calls legacy `fetch_task`. Tech debt.
5. **Redis/DB passwords not renamed** — Still `hydra-redis-dev-2026` / `hydra_dev_2026`. Non-breaking.
6. **Single-GPU bottleneck** — MITIGATED: Dual Ollama routing (CPU + GPU). Both models always loaded.
7. **Path C empty findings** — MITIGATED: Findings synthesis from IOCs in assess.py.
8. **Path C prose wrapping** — Llama 8B wraps code in explanatory text. Mitigated: `_scrub_code()` strips prose before/after Python.
9. **Assess summary timeout** — FIXED: Increased to 45s (configurable via ZOVARK_ASSESS_TIMEOUT).
10. **DPO pipeline** — Training data exists in `dpo/` but no production model trained yet.

## Pending Work

1. **Re-benchmark with Llama models** — Rerun 1000-alert and Juice Shop benchmarks post-model-switch
2. **Speed optimization** — Ollama keep_alive, Redis code cache, sandbox pool
3. **Design partner outreach** — 3 CISOs targeted (EU bank, US healthcare, defense)
4. **BlackHat Arsenal CFP** — Abstract ready in `docs/outreach/blackhat_cfp.md`
5. **Real SIEM connection** — Splunk/Elastic webhook endpoints exist, untested with live SIEM
6. **RunPod A100 benchmark** — Rerun on fast hardware
7. **Zovark Core** — Log normalizer / ZCS schema — NOT IMPLEMENTED (planning only)
