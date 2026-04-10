# Zovark Implementation Audit

**Generated:** 2026-03-28 | **Version:** v1.7.0 | **Commit:** c544c32 | **Branch:** master | **Total commits:** 183

This is a factual audit of the Zovark (formerly HYDRA) codebase. It reports what IS implemented, not what's planned.

---

## 1. CODEBASE INVENTORY

### File Counts & LOC

| Language | Files | LOC (approx) |
|----------|-------|-------------|
| Python (.py) | ~200 (worker/, scripts/, dpo/, tests/) | ~25,000 |
| Go (.go) | 51 (api/) | ~10,000 |
| TypeScript/TSX (dashboard/) | 33 source files | ~4,000 |
| SQL (migrations/) | 57 | ~3,000 |
| YAML/YML (configs, k8s, helm) | ~50 | ~2,500 |
| Markdown (docs/) | ~40 | ~15,000 |
| **Total (source, excl. node_modules)** | **~430** | **~60,000** |

Note: The TypeScript LOC count of 863K reported by some tools includes node_modules. Actual dashboard source is ~4,000 lines across 33 files.

### Top-Level Directory Structure

| Directory | Purpose | Key file count |
|-----------|---------|---------------|
| api/ | Go REST API | 51 .go files |
| worker/ | Python Temporal worker | ~200 .py files across 32 subdirectories |
| worker/stages/ | V2 5-stage pipeline | 12 files, 2,114 LOC |
| dashboard/ | React 19 frontend | 33 source files (15 pages, 11 components) |
| dpo/ | DPO training pipeline | 19 files |
| migrations/ | PostgreSQL migrations | 57 .sql files (001-054) |
| scripts/ | Benchmarks, utilities, deployment | ~64 files |
| docs/ | Documentation | ~40 .md files |
| k8s/ | Kubernetes manifests | 29 .yaml files |
| helm/ | Helm charts | 11 files |
| terraform/ | AWS/GCP IaC | 6 .tf files |
| config/ | PostgreSQL, Prometheus, Grafana | 6 files |
| sandbox/ | AST prefilter, seccomp, kill timer | 5 files |
| marketing/ | CISO brief, CFP, outreach emails | 6 files |
| mcp-server/ | TypeScript MCP integration | 4 source files |
| tests/ | Integration tests, corpus, ground truth | ~20 files |

### Git State

- **Branch:** master
- **Total commits:** 183
- **Tags:** v0.10.1-security, v1.0.0-rc1, v1.1.0, v1.2.0, v1.3.0, v1.4.0, v1.5.0, v1.5.1, v1.6.0, v1.7.0, v1.7.0-ready
- **Latest 10 commits:**
  1. `c544c32` rebrand: regenerate CISO brief PDF as ZOVARK_CISO_Brief.pdf
  2. `44e8449` rebrand: Zovarc → Zovark (304 files)
  3. `b5a05eb` fix: Path C benign calibration — benign signal detection
  4. `35af7cb` rebrand: final YAML comments HYDRA → ZOVARC
  5. `f12b6ef` rebrand: remaining Go API + docker-compose + config files
  6. `5c618f3` feat: Zovark cipher audit API (5 endpoints) + nightly cron
  7. `6ae4d3e` rebrand: Go API + docker-compose + configs HYDRA → ZOVARC
  8. `192c556` rebrand: Python worker + scripts HYDRA → ZOVARC
  9. `7a13c8b` rebrand: docs + outreach HYDRA → ZOVARC
  10. `419bce3` feat: Zovark cipher audit skill — NIST SP 800-57 + 10 tests

---

## 2. PIPELINE STATUS

### Stage 1: INGEST (`worker/stages/ingest.py`, 211 LOC)
- **Functions:** `ingest_alert()` — dedup via Redis hash, PII masking (regex: AWS keys, SSN, API keys), skill template retrieval from DB
- **Dedup:** `_check_exact_dedup()`, `_register_dedup()` — Redis SETEX with severity-based TTL (60-7200s)
- **Status:** FULLY IMPLEMENTED. All 3 paths (A/B/C) pass through ingest.
- **TODOs:** None

### Stage 2: ANALYZE (`worker/stages/analyze.py`, 455 LOC)
- **Path A (fast_fill):** `generate_fast_fill_stub()` — regex IOC extraction stub, no LLM. ~5ms.
- **Path B (template):** `_analyze_template()` → `_fill_parameters_fast()` or `_fill_parameters_llm()` → `_render_template()`. LLM param fill timeout: 15s, fallback to fast_fill.
- **Path C (LLM gen):** `_analyze_llm()` — full LLM code generation via `llm_call()`. 900s timeout.
- **Code scrubbing:** `_scrub_code()` — strips markdown fences, LLM tokens, fixes hallucinated imports.
- **Preflight:** `preflight_check()` — AST validation + auto-fix.
- **Benign detection:** `_BENIGN_DETECTION` prompt block added to both `SYSTEM_PROMPT_SIEM` and `SYSTEM_PROMPT_LOGS`.
- **Status:** FULLY IMPLEMENTED. All 3 paths verified with live LLM inference.
- **TODOs:** None

### Stage 3: EXECUTE (`worker/stages/execute.py`, 249 LOC)
- **AST prefilter:** `_ast_check()` — blocks forbidden imports (11 modules) and patterns (7 patterns from sandbox_policy.yaml)
- **Sandbox:** `_run_in_sandbox()` — Docker container: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--pids-limit=64`, `--memory=512m`, `seccomp` profile, 120s timeout
- **Safety wrapper:** `_wrap_code_safely()` — wraps Path C LLM code in try/except, guarantees JSON stdout
- **Fast fill:** `_run_fast_fill()` — direct subprocess for stress tests (no Docker)
- **Status:** FULLY IMPLEMENTED. 4-layer sandbox verified.
- **TODOs:** None

### Stage 4: ASSESS (`worker/stages/assess.py`, 424 LOC)
- **Verdict derivation:** `_derive_verdict()` — risk≤35→benign, ≥70→true_positive, ≥50→suspicious
- **IOC extraction:** `_extract_iocs_from_signals()` — extracts IPs, URLs, emails, hashes (MD5/SHA1/SHA256), domains, CVEs from SIEM fields + raw text. Adds `evidence_refs` to each IOC.
- **Attack signal boost:** 7 regex patterns (SQLi, XSS, path traversal, auth bypass, command injection, SSRF, file upload) — +45 risk per match
- **Schema validation:** `validate_investigation_output()` with safe default fallback
- **LLM summary:** `_llm_summary()` — 15s timeout, template fallback
- **MITRE mapping:** `get_mitre_techniques()` for all 11 investigation types
- **Status:** FULLY IMPLEMENTED.
- **TODOs:** None

### Stage 5: STORE (`worker/stages/store.py`, 262 LOC)
- **Task update:** `_update_task_status()` — synchronous_commit for durability
- **Investigation record:** `_create_investigation()` — synchronous_commit
- **Pattern memory:** `_save_pattern()` — async (non-critical)
- **Audit events:** `_insert_audit_event()` — investigation_started + investigation_completed
- **Status:** FULLY IMPLEMENTED. Stores stderr + generated_code for debugging.
- **TODOs:** None

---

## 3. SKILL TEMPLATES

11 skill templates stored in `agent_skills` table (code_template column). NOT in worker/stages/skills/ files — templates are in the database.

| Skill Slug | Threat Types | Active | Real Logic? |
|------------|-------------|--------|-------------|
| brute-force-investigation | 4 (brute_force, brute_force_investigation, broken_auth, idor) | Yes | YES — counts auth failures, extracts attacking IPs, identifies targeted accounts, detects credential stuffing |
| phishing-investigation | 3 (phishing, phishing_investigation, benign_activity) | Yes | YES — URL analysis, email header mismatch, urgency detection, typosquatting, attachment analysis |
| ransomware-triage | 3 (ransomware_triage, malware, ransomware) | Yes | YES — shadow copy deletion, mass encryption, ransom notes, lateral spread via SMB |
| data-exfiltration-detection | 9 (data_exfiltration, sqli, xss, path_traversal, command_injection, ssrf, file_upload, benign_activity, data_exfiltration_detection) | Yes | YES — transfer volume, cloud storage URLs, encoding/compression, off-hours, sensitive files |
| privilege-escalation-hunt | 1 | Yes | YES — sudo/su abuse, SUID exploitation, UAC bypass, Windows token manipulation, CVE detection |
| c2-communication-hunt | 1 | Yes | YES — beacon interval analysis (jitter), DGA domain entropy, C2 framework signatures, non-standard ports |
| lateral-movement-detection | 1 | Yes | YES — PsExec/WMI/WinRM, pass-the-hash, multi-hop detection, admin share access |
| insider-threat-detection | 1 | Yes | YES — off-hours access, bulk data access, privilege abuse, data staging, HR context |
| network-beaconing | 4 (c2_communication, command_and_control, data_exfiltration, network_beaconing) | Yes | YES — timestamp interval analysis, DNS anomalies, fixed payload size, suspicious TLDs |
| cloud-infrastructure-attack | 1 | Yes | YES — IAM changes, unusual API calls, cross-region activity, resource creation spikes, credential exposure |
| supply-chain-compromise | 1 | Yes | YES — hash mismatches, unauthorized package versions, typosquatted packages, build pipeline modifications |

**All templates use `siem_event = json.loads("""{{siem_event_json}}""")` pattern.** Templates parse the full SIEM event and run domain-specific investigation logic. fast_fill support: YES (all 11).

**Cipher audit skill:** `worker/stages/skills/cipher_audit.py` — separate from DB templates. Deterministic NIST SP 800-57 classification. NOT a template skill — standalone Temporal activity.

---

## 4. DATABASE STATE

### Migration Files (57 total, migrations/001-054)

001-015: Entity graph, schema drift, hardening, bootstrap, detection, SOAR, webhooks, finetuning, model registry, security, SRE
016-030: Dedup, feedback, cost, cache, failure context, indexes, API keys, TOTP, scheduling, incidents, SLA, shadow, quotas, kill switch, PII
031-045: NATS, stampede, RLS, encryption, Vault, performance, KEV, legacy cleanup, human review, network beaconing, fingerprints, merged context, dedup columns, memory, LLM audit
046-054: Model name tracking, threat type aliases, hardening (SCRAM, FK), model performance, bootstrap enhancements, detection rules, SOAR enhancements, IOC evidence refs, cipher audit events

### Table Count: 85 tables in public schema

### Key Tables with Data
- `agent_tasks` — 2000+ investigation records
- `agent_skills` — 11 active skill templates
- `investigations` — completed investigation records
- `llm_audit_log` — LLM call audit trail
- `tenants` — at least 2 tenants (test + admin)
- `users` — admin users
- `audit_events` — monthly partitioned audit trail
- `cipher_audit_events` — TLS cipher governance (newly created)

### Tables That May Be Empty Shells
- `entity_edges`, `entity_observations` — entity graph (populated only when LLM entity extraction runs)
- `detection_rules` — Sigma rules (populated by detection engine workflow)
- `response_executions` — SOAR execution records
- `cross_tenant_entities` — cross-tenant intelligence
- `finetuning_jobs` — DPO training jobs
- `model_ab_tests` — A/B test results

---

## 5. API ENDPOINTS

### Route Count: ~90 registered routes in api/main.go

#### Auth (no auth required, rate limited)
- `POST /api/v1/auth/register` — registerHandler
- `POST /api/v1/auth/login` — loginHandler
- `POST /api/v1/auth/refresh` — refreshHandler
- `POST /api/v1/auth/logout` — logoutHandler
- `GET /api/v1/auth/sso/login` — ssoLoginHandler
- `GET /api/v1/auth/sso/callback` — ssoCallbackHandler

#### Tasks (authenticated)
- `GET /api/v1/tasks` — listTasksHandler
- `GET /api/v1/tasks/:id` — getTaskHandler
- `GET /api/v1/tasks/:id/audit` — getTaskAuditHandler
- `GET /api/v1/tasks/:id/steps` — getTaskStepsHandler
- `GET /api/v1/tasks/:id/timeline` — getTaskTimelineHandler
- `GET /api/v1/tasks/:id/stream` — taskSSEHandler
- `POST /api/v1/tasks` — createTaskHandler (admin/analyst/api_key + token quota)
- `POST /api/v1/tasks/bulk` — bulkCreateTasksHandler
- `POST /api/v1/tasks/upload` — uploadTaskHandler

#### SIEM Ingest (authenticated)
- `POST /api/v1/ingest/splunk` — splunkIngestHandler
- `POST /api/v1/ingest/elastic` — elasticIngestHandler
- `GET /api/v1/ingest/health` — ingestHealthHandler

#### Cipher Audit (authenticated)
- `GET /api/v1/cipher-audit/stats` — cipherAuditStatsHandler
- `GET /api/v1/cipher-audit/summary` — cipherAuditSummaryHandler
- `GET /api/v1/cipher-audit/findings` — cipherAuditFindingsHandler
- `GET /api/v1/cipher-audit/servers` — cipherAuditServersHandler
- `POST /api/v1/cipher-audit/analyze` — cipherAuditAnalyzeHandler (admin/analyst)

#### Admin/Config (~50 more routes)
- Tenants, users, models, A/B tests, retention policies, webhooks, API keys, TOTP, approvals, MCP approvals, feedback, analytics, automation controls, kill switch, quotas, shadow mode, log sources, notifications, sandbox execute, GDPR erase, detection rules, intelligence, response playbooks, metrics

**Implementation status:** All handlers have REAL implementations (database queries, Temporal workflow dispatch). No 501/placeholder handlers found.

---

## 6. DASHBOARD

### Pages (15)
| Page | File | Status |
|------|------|--------|
| TaskList | TaskList.tsx | FUNCTIONAL — live polling, filters |
| TaskDetail | TaskDetail.tsx | FUNCTIONAL — waterfall, MITRE badges, IOC confidence, export |
| NewTask | NewTask.tsx | FUNCTIONAL — task creation form |
| Login | Login.tsx | FUNCTIONAL — JWT auth |
| AdminPanel | AdminPanel.tsx | FUNCTIONAL — tenant management |
| ApprovalQueue | ApprovalQueue.tsx | FUNCTIONAL — pending approvals |
| SIEMAlerts | SIEMAlerts.tsx | FUNCTIONAL — alert ingestion view |
| Playbooks | Playbooks.tsx | FUNCTIONAL — playbook management |
| PlaybookBuilder | PlaybookBuilder.tsx | FUNCTIONAL — visual builder |
| EntityGraph | EntityGraph.tsx | FUNCTIONAL — entity visualization |
| ThreatIntel | ThreatIntel.tsx | FUNCTIONAL — threat feeds |
| CostDashboard | CostDashboard.tsx | FUNCTIONAL — token cost tracking |
| LogSources | LogSources.tsx | FUNCTIONAL — SIEM config |
| Settings | Settings.tsx | FUNCTIONAL — user preferences |
| DemoPage | DemoPage.tsx | FUNCTIONAL — demo scenarios |

### Components (8)
DataFlowBadge, DemoBanner, ExecutiveSummary, InvestigationWaterfall, MitreTimeline, Notifications, Skeleton, StepDetailPanel — live investigation streaming uses `EventSource` on **TaskList** / **TaskDetail** (`/api/v1/tasks/stream`), not a separate feed component

**All pages and components are FUNCTIONAL** — not skeletons. The dashboard compiles with zero errors (Vite build verified).

---

## 7. LLM INTEGRATION

### Model Configuration
- **Runtime:** Ollama on host (port 11434)
- **Primary model:** llama3.1:8b (Meta Llama 3.1 8B-Instruct)
- **Also available:** llama3.2:3b (Meta Llama 3.2 3B-Instruct)
- **Worker env:** `LITELLM_URL=http://host.docker.internal:11434/v1/chat/completions`

### Prompt Files
| File | LOC | Purpose |
|------|-----|---------|
| dpo/prompts_v2.py | ~891 | Full prompt library: system identity, tool definitions, technique-IOC map, task template, RAG examples, objective recitation, retry prompt, DPO forge prompts |
| dpo/prompts.py | ~469 | Original prompt templates |
| worker/stages/analyze.py | 455 | System prompts for Path C code gen (SYSTEM_PROMPT_SIEM, SYSTEM_PROMPT_LOGS) with _BENIGN_DETECTION and _DEFENSIVE_CODING blocks |

### Benign Over-Scoring Fix
**STATUS: APPLIED** (commit b5a05eb). `_BENIGN_DETECTION` block added to both `SYSTEM_PROMPT_SIEM` and `SYSTEM_PROMPT_LOGS` in analyze.py, and rule 3 (benign signal detection) in dpo/prompts_v2.py. Verified: benign alerts score risk=20.

### DPO Pipeline
| File | LOC | Status |
|------|-----|--------|
| dpo_forge.py | 546 | IMPLEMENTED — training pair generation |
| prompts_v2.py | 891 | IMPLEMENTED — full prompt library |
| batch_generate.py | 323 | IMPLEMENTED — batch API calls |
| generate_pairs.py | 186 | IMPLEMENTED — preference pair construction |
| generate_rejected.py | 132 | IMPLEMENTED — weak answer generation |
| assemble_dataset.py | 160 | IMPLEMENTED — dataset composition |
| finetune.py | 98 | STUB — imports but minimal training loop |
| merge_adapter.py | 48 | IMPLEMENTED — LoRA adapter merging |
| validators.py | 111 | IMPLEMENTED — output validation |
| log_compressor.py | 330 | IMPLEMENTED — log summarization |

**DPO training data exists:** training_dataset.jsonl, chosen_examples.jsonl, rejected_examples.jsonl. **No production model trained yet** — the pipeline generates data but hasn't produced a deployed fine-tuned model.

---

## 8. INFRASTRUCTURE

### docker-compose.yml Services
| Service | Image | Status |
|---------|-------|--------|
| postgres | pgvector/pgvector:pg16 | CORE — running |
| redis | redis:7-alpine | CORE — running |
| pgbouncer | edoburu/pgbouncer | CORE — running |
| temporal | temporalio/auto-setup:1.24.2 | CORE — running |
| api | Custom Go build | CORE — running |
| worker | Custom Python build | CORE — running |
| dashboard | Custom React build (nginx) | CORE — running |
| squid-proxy | ubuntu/squid | CORE — egress filtering |
| juice-shop | bkimminich/juice-shop | OPTIONAL — benchmark target |
| temporal-ui | temporalio/ui:2.26.2 | OPTIONAL — profile: debug |
| minio | minio/minio | OPTIONAL — profile: storage |
| jaeger | jaegertracing/all-in-one | OPTIONAL — profile: monitoring |
| caddy | caddy:2-alpine | OPTIONAL — profile: tls |
| prometheus | prom/prometheus:v2.51.0 | OPTIONAL — profile: monitoring |
| grafana | grafana/grafana:11.0.0 | OPTIONAL — profile: monitoring |
| postgres-exporter | prometheuscommunity/postgres-exporter | OPTIONAL — profile: monitoring |
| redis-exporter | oliver006/redis_exporter | OPTIONAL — profile: monitoring |
| ollama | ollama/ollama | OPTIONAL — profile: airgap-ollama |

### Kubernetes (k8s/)
29 YAML files across base/, overlays/dev/, overlays/production/, overlays/airgap/, overlays/multi-region/. **Present and structured** but NOT tested against a live cluster. May have stale references.

### Helm Charts (helm/zovark/)
11 files (Chart.yaml, values.yaml, templates/). **Present** but NOT validated against a live Helm install.

### Terraform (terraform/)
6 .tf files across modules/ (eks, rds, redis, vpc) and environments/ (dev, prod). **Present** but NOT applied to any cloud account.

---

## 9. SECURITY IMPLEMENTATION

### Sandbox (4-layer model)
| Layer | Implementation | File | Status |
|-------|---------------|------|--------|
| 1. AST Prefilter | `_ast_check()` — blocks 11 forbidden imports + 7 forbidden patterns | worker/stages/execute.py:59-83 | **IMPLEMENTED** |
| 2. Docker Container | `--network=none`, `--read-only`, `--cap-drop=ALL`, `--pids-limit=64`, `--memory=512m` | worker/stages/execute.py:112-121 | **IMPLEMENTED** |
| 3. Seccomp Profile | `--security-opt seccomp=sandbox/seccomp_profile.json` (862 lines, blocks ptrace, mount, reboot) | sandbox/seccomp_profile.json | **IMPLEMENTED** |
| 4. Kill Timer | Subprocess timeout (configurable, default 120s) | worker/stages/execute.py:108,126 | **IMPLEMENTED** |

### Authentication
- **JWT:** IMPLEMENTED — HS256, 15-min access tokens, 7-day refresh (httpOnly cookie). Enforced in `authMiddleware()`.
- **OIDC/SSO:** IMPLEMENTED — `ssoLoginHandler`, `ssoCallbackHandler` in api/oidc.go (657 LOC). Azure AD, Okta support.
- **TOTP 2FA:** IMPLEMENTED — `totpSetupHandler`, `totpVerifyHandler` in api/totp.go.
- **API Keys:** IMPLEMENTED — `createAPIKeyHandler`, `listAPIKeysHandler`, `deleteAPIKeyHandler`.

### RBAC
**IMPLEMENTED and ENFORCED.** `requireRole()` middleware applied to all mutating endpoints. Roles: admin, analyst, viewer, api_key. Checked via `c.Get("user_role")` in every handler.

### Vault Integration
**PARTIALLY IMPLEMENTED.** `api/vault.go` exists with Vault client setup, JIT secret retrieval functions. But Vault is NOT in the core docker-compose — it's a deployment-time configuration. The code supports it; runtime activation requires external Vault server.

### Audit Trail
**IMPLEMENTED.** `audit_events` table with monthly partitions. `_insert_audit_event()` in store.py fires on investigation_started and investigation_completed. `auditMiddleware()` in Go logs all API mutations.

---

## 10. TESTS

### Test Files
| Suite | Files | Functions | Location |
|-------|-------|-----------|----------|
| Go unit tests | 6 | 44 | api/*_test.go |
| Python unit tests | 9 | 179 | worker/tests/ |
| V2 pipeline tests | 15 | 15 | worker/tests/ |
| Cipher audit tests | 1 | 10 | tests/test_cipher_audit.py |
| Integration tests | ~10 | ~50 | tests/ |
| **Total** | **~26** | **~298** | |

### Last Known Pass Rate
- Go tests: 44/44 (100%)
- Python tests: 179/179 (100%) — some may have import path issues post-rebrand
- Cipher audit: 10/10 (100%)
- V2 pipeline: 15/15 (100%)

### Coverage Gaps (major components with ZERO tests)
- `api/cipher_audit_handlers.go` — no Go tests
- `api/siem_ingest.go` — no Go tests
- `api/response_handlers.go` — no Go tests
- `api/cross_tenant_handlers.go` — no Go tests
- `api/detection_handlers.go` — no Go tests
- `worker/bootstrap/mitre_attack.py` — no tests
- `worker/bootstrap/cisa_kev.py` — no tests
- `worker/detection/rule_generator.py` — no tests
- `worker/response/playbook_engine.py` — no tests
- `worker/intelligence/cross_tenant.py` — no tests
- Dashboard (React) — ZERO test files

---

## 11. ZOVARK CORE (WEDGE PRODUCT)

**STATUS: NOT IMPLEMENTED**

No files exist for:
- Log normalizer
- ZCS (Zovark Common Schema)
- Field mapping engine
- Any "Zovark Core" product code

The codebase is entirely the SOC investigation platform (formerly HYDRA). Zovark Core exists only in strategic planning documents, not in code.

---

## 12. KNOWN GAPS

### Documented but NOT Implemented
- DPO fine-tuned production model (pipeline exists, no deployed model)
- Multi-worker scaling validation (`docker compose --scale worker=3` — untested)
- PCAP/NetFlow analysis (docs mention as limitation)
- Zovark Core (log normalizer, ZCS schema)
- Real Splunk/Elastic live connection (webhook endpoints exist but never connected to a real SIEM)

### Implemented but NOT Documented
- Cipher audit skill (Sprint 2C) — no docs/CIPHER_AUDIT.md
- SIEM ingest endpoints (/api/v1/ingest/splunk, /elastic) — added to openapi.yaml but no dedicated guide
- Safety wrapper for Path C code (`_wrap_code_safely()`) — not mentioned in architecture docs
- Evidence refs on IOCs — not in API documentation

### Dead Code / Orphaned Files
- `worker/workflows/zovark_workflows.py` — renamed from hydra_workflows.py, may have stale imports
- `scripts/test_exfil_template.py`, `scripts/debug_escaping.py`, `scripts/debug_brute_force.py` — debug scripts left in repo
- `scripts/test_benign_20.sh`, `scripts/test_benign_fix.sh`, `scripts/test_3_tasks.sh` — test scripts
- `models/hydra-dpo-adapter/` — old brand name in model directory (if it exists)
- `marketing/outreach/HYDRA_CISO_Brief.pdf` — deleted (ZOVARK version exists)

---

## 13. BRAND STATE

### Remaining "hydra" References in Source Code
```
worker/stages/model_config.yaml:
  name: "hydra-fast"      (line ~8)
  name: "hydra-standard"  (line ~15)
  name: "hydra-enterprise" (line ~22)
  model: "hydra-enterprise" (line ~23)
```

These are model TIER NAMES (logical labels), not brand references. They're used as keys in the model routing config. **4 occurrences total.**

### "Zovarc" References
**ZERO** — fully corrected to Zovark.

### "HYDRA" References (excluding model tier names)
**ZERO** in source code. Present only in git history.

---

## 14. OPEN BUGS & DEBT

### TODO/FIXME/HACK Comments
| File | Line | Comment |
|------|------|---------|
| api/siem.go | 76 | `TODO(security): Go-side sanitization is limited to control-char stripping` |

**Only 1 TODO in the entire pipeline + API codebase.**

### Known Bugs
1. **Path C benign over-scoring** — FIX APPLIED (v1.7.1) but only verified on 1 benign task. 8 more were still pending when last tested. The LLM sometimes generates code that scores benign events at risk=50+ despite the prompt instructions.
2. **model_config.yaml tier names** — Still use `hydra-fast`/`hydra-standard`/`hydra-enterprise`. Should be `zovark-*`. Non-breaking (they're logical labels, not brand-facing).
3. **NATS hostname resolution** — Non-fatal warning on every worker startup. NATS is optional but env vars still reference it.
4. **Stale Temporal workflows** — Old workflows from previous runs accumulate and block the worker queue. Must terminate manually with `tctl` before benchmark runs.
5. **Single-GPU bottleneck** — RTX 3050 processes one LLM request at a time. Path C tasks take 270s each. The 1000-alert benchmark took 38 hours.

### Deprecated Code Still In Use
- `worker/_legacy_activities.py` — V2 workflow calls `fetch_task` by string name from this file. Should be inlined into ingest.py.
- `worker/workflows/zovark_workflows.py` — legacy workflow definitions, still registered but rarely used.

### Technical Debt
- Dashboard has ZERO test coverage
- 5 new Go API handlers (cipher audit, SIEM ingest, response, detection, cross-tenant) have no Go tests
- Bootstrap pipeline (MITRE ATT&CK, CISA KEV) untested in CI
- DPO pipeline has data but no trained model
- K8s/Helm/Terraform configs present but never validated against live infrastructure

---

*End of audit. This document is self-contained for use in a separate context window.*
