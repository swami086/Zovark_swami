# ZOVARK — Autonomous AI SOC Agent

> Air-gapped SOC investigation platform for regulated enterprises (GDPR/HIPAA/CMMC).
> Receives SIEM alerts → generates investigation code → executes in sandbox → delivers structured verdicts.
> Rebranded from HYDRA → Zovarc → Zovark. All source files use "Zovark" branding.

## Quick Reference

- **Version:** v1.8.1 (latest: `git log -1 --format=%h`)
- **Commits:** 190+ on master
- **Status:** Production-ready — 100% attack detection, 0% FP on 200-benign calibration
- **Stack:** Go API + Python Temporal Worker + React Dashboard + PostgreSQL/pgvector + Redis + Ollama (Qwen2.5-14B)
- **Pipeline:** V2 5-stage with LLM audit gateway, schema validation, MITRE mapping, evidence citations
- **LLM:** Qwen2.5-14B-Instruct Q4_K_M via Ollama on host (:11434). **No litellm dependency.**
- **Tests:** 44 Go + 179 Python + 15 V2 pipeline + 10 cipher audit = 248 test functions
- **Services:** 8 core Docker containers + optional monitoring/storage
- **Dashboard:** React 19 + Vite 7 + Tailwind 4, 15 pages, dark mode, MITRE ATT&CK badges

## Critical: Credentials & Passwords

- **Admin:** admin@test.local / TestPass2026 (tenant e1c1bc5d)
- **DB:** user=zovark, password=hydra_dev_2026 (password NOT renamed during rebrand), db=zovark
- **Redis:** password=hydra-redis-dev-2026 (NOT renamed during rebrand)
- **LLM endpoint:** `ZOVARK_LLM_ENDPOINT=http://host.docker.internal:11434/v1/chat/completions`
- **LLM key:** `ZOVARK_LLM_KEY=sk-zovark-dev-2026`

## Architecture (V2 Pipeline)

```
SIEM Alert → Go API (:8090) → Temporal → InvestigationWorkflowV2 →

  Stage 1 INGEST   [NO LLM]  Dedup (Redis) → PII mask → skill retrieval → attack indicator check
  Stage 2 ANALYZE  [LLM ①]   Path A: template fast-fill (~350ms)
                              Path B: template + LLM param fill (~30-90s)
                              Path C: full LLM code generation (~120-280s)
  Stage 3 EXECUTE  [NO LLM]  AST prefilter → Docker sandbox (network=none, seccomp, 512MB, 120s)
                              Safety wrapper on Path C (guarantees JSON on crash, risk=0 not 50)
  Stage 4 ASSESS   [LLM ②]   Verdict derivation → IOC extraction with evidence_refs → MITRE mapping
                              Attack signal boost (7 regex patterns: SQLi, XSS, etc.)
                              Benign: risk≤35 → benign unconditionally
  Stage 5 STORE    [NO LLM]  agent_tasks + investigations + audit_events + memory

  → Structured Verdict: findings, IOCs (with evidence_refs), risk_score, verdict, MITRE ATT&CK
```

### Three Code Paths (all verified with live LLM inference)

| Path | Trigger | Speed | Example |
|------|---------|-------|---------|
| A (template) | task_type matches skill template | ~350ms | brute_force, phishing, ransomware |
| B (template + LLM fill) | template + LLM param extraction | ~30-90s | lateral_movement with enriched SIEM |
| C (full LLM gen) | no matching template | ~120-280s | kerberoasting, golden_ticket, defense_evasion |
| Benign | task_type matches benign-system-event template | ~350ms | password_change, windows_update, health_check |

### Benign Routing (Inverted Logic)

`worker/stages/ingest.py` has `ATTACK_INDICATORS` list. If task_type/rule_name/title do NOT match any attack indicator, the alert routes to the `benign-system-event` skill template (31 benign task types registered). This means novel benign alerts default to benign, not to expensive LLM Path C.

## Key Files

| File | LOC | Purpose |
|------|-----|---------|
| `worker/stages/ingest.py` | 230 | Stage 1: dedup, PII mask, skill retrieval, attack indicator check |
| `worker/stages/analyze.py` | 460 | Stage 2: Path A/B/C code generation, system prompts |
| `worker/stages/execute.py` | 260 | Stage 3: AST prefilter, Docker sandbox, safety wrapper |
| `worker/stages/assess.py` | 430 | Stage 4: verdict, IOC extraction, evidence_refs, MITRE, signal boost |
| `worker/stages/store.py` | 270 | Stage 5: DB writes, audit events, synchronous_commit |
| `worker/stages/llm_gateway.py` | 180 | LLM call routing, audit logging, keep_alive, preload |
| `worker/stages/output_validator.py` | 95 | Schema validation, IOC normalization, benign empty-findings allowed |
| `worker/stages/mitre_mapping.py` | 83 | MITRE ATT&CK technique mapping for 11 types |
| `worker/stages/investigation_workflow.py` | 110 | InvestigationWorkflowV2 orchestrator |
| `worker/stages/skills/cipher_audit.py` | ~200 | Cipher audit skill (NIST SP 800-57) |
| `dpo/prompts_v2.py` | ~900 | Full prompt library (system, task, tools, RAG, retry, DPO) |
| `api/main.go` | 320 | Go API router, ~90 registered routes |
| `api/siem_ingest.go` | 340 | Splunk HEC + Elastic SIEM webhook ingest |
| `api/cipher_audit_handlers.go` | ~300 | 5 cipher audit API endpoints |

## Database

- **Engine:** PostgreSQL 16 + pgvector
- **User:** zovark (password: hydra_dev_2026)
- **Database:** zovark
- **Tables:** 85+
- **Migrations:** 54 files (001-054)
- **Connection pooling:** PgBouncer (400 client / 25 server)
- **Key tables:** agent_tasks, investigations, agent_skills (12 templates), llm_audit_log, cipher_audit_events, audit_events (partitioned), entities, entity_edges, detection_rules, response_playbooks, cross_tenant_entities

## Skill Templates (12 total)

11 attack investigation templates + 1 benign template, stored in `agent_skills.code_template`:

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

## Docker Services

### Core (always run)
| Service | Image | Port | Container Name |
|---------|-------|------|---------------|
| postgres | pgvector/pgvector:pg16 | 5432 | zovark-postgres |
| redis | redis:7-alpine | 6379 | zovark-redis |
| pgbouncer | edoburu/pgbouncer | 6432 | zovark-pgbouncer |
| temporal | temporalio/auto-setup:1.24.2 | 7233 | zovark-temporal |
| api | Custom Go build | 8090 | zovark-api |
| worker | Custom Python build | — | zovark-worker |
| dashboard | Custom React (nginx) | 3000 | zovark-dashboard |
| squid-proxy | ubuntu/squid | 3128 | zovark-egress-proxy |

### Optional (profiles)
- temporal-ui (debug), minio (storage), jaeger (monitoring), caddy (tls)
- prometheus, grafana, postgres-exporter, redis-exporter (monitoring profile)
- ollama (airgap-ollama profile — for when Ollama isn't on host)

### LLM (runs on HOST, not Docker)
- **Ollama** on port 11434 with `qwen2.5:14b` model
- Worker connects via `http://host.docker.internal:11434/v1/chat/completions`
- **litellm is NOT used** — removed due to supply chain risk (PyPI 1.82.7-1.82.8 compromised)
- Env var: `ZOVARK_LLM_ENDPOINT` (not LITELLM_URL — fully renamed)

## Benchmarks

| Benchmark | Result |
|-----------|--------|
| 1000-alert corpus | 983/1000 completed, 100% attack detection, 0 false negatives |
| Juice Shop (100 real-traffic) | 99/100 accuracy (70/70 attacks, 29/30 benign) |
| 200-benign calibration | 200/200 benign, 0% false positive rate |
| Path C novel attacks (10 types) | 10/10 correct (kerberoasting, golden_ticket, LOLBins, etc.) |
| Template fast-fill throughput | ~350ms per investigation |

## Security Implementation

| Layer | What | Status |
|-------|------|--------|
| AST Prefilter | Blocks os/sys/subprocess/socket/eval/exec + 7 patterns | IMPLEMENTED |
| Docker Sandbox | network=none, read-only, cap-drop ALL, 512MB, 64 PIDs, seccomp | IMPLEMENTED |
| Kill Timer | 120s subprocess timeout | IMPLEMENTED |
| Safety Wrapper | Path C code wrapped in try/except, risk=0 on crash (not 50) | IMPLEMENTED |
| JWT Auth | 15min access + 7d refresh (httpOnly cookie) | IMPLEMENTED |
| RBAC | admin/analyst/viewer/api_key enforced in middleware | IMPLEMENTED |
| OIDC/SSO | Azure AD, Okta (api/oidc.go, 657 LOC) | IMPLEMENTED |
| TOTP 2FA | RFC 6238 (api/totp.go) | IMPLEMENTED |
| Audit Trail | audit_events table, monthly partitions | IMPLEMENTED |
| Synchronous Commit | Critical writes use `SET LOCAL synchronous_commit = on` | IMPLEMENTED |
| Evidence Citations | Every IOC has evidence_refs linking to source log line | IMPLEMENTED |
| Zero Hallucination | Prompt rules forbid inventing IOCs not in log data | IMPLEMENTED |

## Coding Conventions

- **Tenant isolation:** Every DB query MUST include `tenant_id` in WHERE clause
- **Error handling (Go):** Use `respondInternalError()` — never expose `err.Error()` to clients
- **LLM calls:** Always through `worker/stages/llm_gateway.py` via `ZOVARK_LLM_ENDPOINT`
- **No litellm:** Direct httpx POST to Ollama. Zero AI proxy libraries.
- **Sandbox code:** Must pass AST prefilter — no `os`, `sys`, `subprocess`, `socket`
- **Skill templates:** Stored in `agent_skills.code_template` column, use `{{siem_event_json}}` placeholder
- **New activities:** Add to `worker/stages/*.py`, register in `worker/stages/register.py`
- **Migrations:** Sequential in `migrations/`, apply via `docker compose exec -T postgres psql -U zovark -d zovark < migrations/NNN_name.sql`
- **After Python changes:** `docker compose build worker && docker compose up -d worker`
- **After Go changes:** `docker compose build api && docker compose up -d api`
- **Before benchmarks:** Terminate stale Temporal workflows: `docker exec zovark-temporal tctl --ad temporal:7233 --ns default workflow list --open` then terminate each

## How to Run

```bash
# Start all services
docker compose up -d

# Start Ollama on host (if not already running)
ollama serve  # or: ollama run qwen2.5:14b

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

## Key Docs

| Doc | Path |
|-----|------|
| Implementation Audit | `docs/ZOVARK_IMPLEMENTATION_AUDIT.md` |
| Architecture | `docs/ARCHITECTURE.md` |
| API Spec | `docs/openapi.yaml` |
| Whitepaper | `docs/WHITEPAPER.md` |
| Sandbox Security | `docs/SANDBOX_SECURITY.md` |
| SIEM Integration | `docs/SIEM_INTEGRATION.md` |
| Juice Shop Benchmark | `docs/JUICE_SHOP_BENCHMARK.md` |
| BlackHat CFP | `docs/outreach/blackhat_cfp.md` |
| CISO Brief (PDF) | `marketing/outreach/ZOVARK_CISO_Brief.pdf` |
| Cold Email Templates | `docs/outreach/outreach_templates.md` |
| Demo Script | `docs/outreach/demo_talking_points.md` |

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

## Known Issues

1. **NATS hostname resolution** — Non-fatal warning on worker startup. NATS is optional.
2. **Stale Temporal workflows** — Must terminate before benchmark runs: `tctl workflow terminate`.
3. **`investigation_memory` table** — Name is SINGULAR. Plural reference silently fails.
4. **`fetch_task` dependency** — V2 workflow still calls legacy `fetch_task`. Tech debt.
5. **Redis password not renamed** — Still `hydra-redis-dev-2026` (not `zovark-*`). Non-breaking.
6. **DB password not renamed** — Still `hydra_dev_2026` for user `zovark`. Non-breaking.
7. **model_config.yaml tier names** — Renamed to `zovark-fast`/`zovark-standard`/`zovark-enterprise`.
8. **Single-GPU bottleneck** — RTX 3050 serializes LLM requests. Path C takes 120-280s.
9. **Path C benign** — LLM sometimes over-scores benign (55-60 instead of ≤25). Mitigated by benign-system-event template routing.
10. **DPO pipeline** — Data exists but no production model trained.

## Pending Work

1. **Speed optimization** — Ollama keep_alive, Redis code cache, sandbox pool, 7B model for param fill
2. **Design partner outreach** — 3 CISOs targeted (EU bank, US healthcare, defense)
3. **BlackHat Arsenal CFP** — Abstract ready in `docs/outreach/blackhat_cfp.md`
4. **Real SIEM connection** — Splunk/Elastic webhook endpoints exist, untested with live SIEM
5. **RunPod A100 benchmark** — Rerun 1000-alert benchmark on fast hardware (~2h vs 38h)
6. **Zovark Core** — Log normalizer / ZCS schema — NOT IMPLEMENTED (planning only)
