# ZOVARK MVP — Final Audit Report

**Date:** 2026-03-14
**Branch:** master @ `f5fb15f`
**Remote:** https://github.com/7inaydas-cmyk/zovark-mvp.git
**Status:** All sprints through v0.10.1 complete

---

## A. Sprint Status Table

| # | Sprint | Description | Commit | Status |
|---|--------|-------------|--------|--------|
| 1 | Sprint 12 | Test framework (20/20 harness + 5/5 integration) | `9d7c691` | DONE |
| 2 | Block 1.1 | Stateless worker + worker identity tracking | `74931d6` | DONE |
| 3 | Block 1.2 | Multi-worker scaling (docker compose --scale) | `329aac3` | DONE |
| 4 | Block 1.3 | PgBouncer + Postgres tuning + Redis rate limiting + table partitioning | `fb76387` | DONE |
| 5 | Block 1.4a | Load testing (baseline 17 inv/min, scaled 21, stress 100) | `986809f` | DONE |
| 6 | Block 1.4b | Kubernetes manifests — Kustomize + HPA + NetworkPolicy + 3 overlays | `0fd15af` | DONE |
| 7 | Block 1.5 | K8s deployment verification (no cluster, manifests validated) | `f52f070` | DONE |
| 8 | Sprint 1E | Production hardening — sandbox limits, SCRAM-SHA-256, audit events | `e433104` | DONE |
| 9 | Sprint 1F | Bootstrap corpus — MITRE ATT&CK (691) + CISA KEV (1536) + synthetic investigations | `59753e0` | DONE |
| 10 | Sprint 1G | Entity graph — investigations, entities, edges, observations + normalization + extraction | `e60bbd3` | DONE |
| 11 | Sprint 1H | Bootstrap entity graph at scale — 100 synthetic, 240 entities, 216 edges | `f0a99f7` | DONE |
| 12 | Sprint 1I | Model tiering + prompt versioning + LLM call logging | `45cdc2e` | DONE |
| 13 | Sprint 1J | Lease-based rate limiting + KEDA autoscaling + Temporal queue depth exporter | `abf5fe1` | DONE |
| 14 | Sprint 1K | Cross-tenant entity resolution — materialized views, threat scoring, privacy-safe API | `ea838d2` | DONE |
| 15 | Sprint 1L | Golden Path — blast radius, deobfuscation, incident reports, FP confidence + injection defense | `5a9ac30` | DONE |
| 16 | Sprint 2A | Self-generating detection engine — pattern mining + Sigma rule generation + validation | `c798ae5` | DONE |
| 17 | Sprint 2B | SOAR response playbooks — 7 action types, 5 default playbooks, auto-trigger | `6054579` | DONE |
| 18 | Sprint 3A | CI/CD pipeline + health endpoint + structured logging | — | DONE |
| 19 | Sprint 3B | Observability — Prometheus + Grafana + exporters + alert rules | — | DONE |
| 20 | Sprint 3C | Tenant CRUD API + webhooks + per-tenant rate limits | — | DONE |
| 21 | Sprint 3D | Fine-tuning data pipeline + quality scoring + model evaluation | — | DONE |
| 22 | Sprint 3E | Model registry + A/B testing + dynamic routing | — | DONE |
| 23 | Sprint 3F | Security hardening — audit middleware, auth rate limiting, lockout, retention | — | DONE |
| 24 | Sprint 4A | Self-healing SRE agent — scan, diagnose, patch, test, apply (dry-run) | — | DONE |
| 25 | Sprint 4C | MCP server — 7 tools, 7 resources, 6 prompts (TypeScript) | — | DONE |
| 26 | Sprint 5 | Multi-provider LLM fallback, dry-run gate, investigation memory, alert dedup | — | DONE |
| 27 | Sprint 6 | Investigation dashboard — waterfall visualization + C2 beacon demo | — | DONE |
| 28 | Sprint 7 | Executive ribbon, air-gap fallback, feedback, cost tracking, accuracy framework | — | DONE |
| 29 | Sprint 9 (v0.9.0) | 55 GitHub issues — OIDC, API keys, TOTP, dashboard 6 pages, testing, deployment | `29eb31b` | DONE |
| 30 | Sprint 10 (v0.10.0) | Shadow Mode — NATS, PII detection, token quotas, kill switch, anti-stampede | `8825b39` | DONE |
| 31 | v0.10.1-security | 5 critical fixes — ports, JWT secret, expiration, OIDC JWKS, httpOnly cookies | `f5fb15f` | DONE |

**Total commits on master:** 31 sprints delivered

---

## B. Complete Table Inventory

### Core Tables (init.sql baseline)

| Table | Rows | Sprint | Notes |
|-------|------|--------|-------|
| tenants | 3 | Baseline | Zovark Dev + Shield MSSP + Acme Security |
| users | 5 | Baseline | |
| agent_tasks | 10 | Baseline | |
| agent_task_steps | 0 | Baseline | |
| agent_skills | 0 | Baseline | |
| agent_audit_log | — | Baseline | Legacy audit table |
| agent_memory_episodic | — | Baseline | |
| agent_personas | — | Baseline | |
| investigation_steps | 16 | Baseline | |
| investigation_memory | — | Baseline | |
| working_memory_snapshots | — | Baseline | |
| approval_requests | 6 | Baseline | |
| usage_records | — | Baseline | |
| object_refs | — | Baseline | |
| log_sources | — | Baseline | |
| siem_alerts | — | Baseline | |
| playbooks | — | Baseline | Legacy playbooks table |

### Sprint Tables

| Table | Rows | Sprint | Notes |
|-------|------|--------|-------|
| investigations | 138 | 1G | Partitioned by month (13 partitions), 134 embedded |
| entities | 304 | 1G | 8 entity types, cross-tenant dedup via entity_hash |
| entity_edges | 258 | 1G | 9 edge types |
| entity_observations | 588 | 1G | 8 roles |
| mitre_techniques | 691 | 1F | All 691 embedded (768-dim) |
| bootstrap_corpus | 1636 | 1F | 1536 CISA KEV + 100 MITRE synthetic |
| audit_events | 21 | 1E | Partitioned by month (13 partitions) |
| investigation_reports | 4 | 1L | 2 markdown + 2 PDF |
| llm_call_log | 16 | 1I | Tracks model tier, tokens, latency, cost |
| detection_candidates | 14 | 2A | All 14 approved |
| detection_rules | 14 | 2A | 14 active Sigma rules, 100% TP avg |
| response_playbooks | 5 | 2B | 5 threat-type playbooks |
| response_executions | 2 | 2B | 2 completed test executions |
| response_integrations | 0 | 2B | Ready for webhook configuration |

### Materialized Views

| View | Sprint | Notes |
|------|--------|-------|
| cross_tenant_intel | 1K | Entities seen by 2+ tenants (29 entities) |
| model_performance | 1I | LLM call aggregations by model/activity/prompt |

### Regular Views

| View | Sprint | Notes |
|------|--------|-------|
| v_task_summary | Baseline | Task + cost summary |
| cross_tenant_public | 1K | Privacy-safe (strips tenant_ids) |

---

## C. Complete File Inventory

> **Archive update (2026):** The tree below reflects the **baseline snapshot** taken for this audit. In the current repo, core activities live in **`worker/_legacy_activities.py`** (re-exported via `worker/activities/__init__.py`), and the main investigation orchestrator is **`InvestigationWorkflowV2`** in **`worker/stages/investigation_workflow.py`** (registered through **`worker/stages/register.py`**), replacing legacy **`ExecuteTaskWorkflow`** in monolithic **`worker/workflows.py`**.

### Worker Python Files (39+ files)

| File | Lines | Sprint | Purpose |
|------|-------|--------|---------|
| worker/activities.py | 940 | Baseline | 19 Temporal activities (core pipeline) — **today:** `worker/_legacy_activities.py` + package `worker/activities/` |
| worker/workflows.py | 1068 | Baseline | **Was** ExecuteTaskWorkflow (main investigation pipeline) — **today:** `worker/stages/investigation_workflow.py` (**InvestigationWorkflowV2**) |
| worker/main.py | 65 | Baseline | Worker entrypoint, registers 10 workflows + 95 activities |
| worker/entity_graph.py | 445 | 1G | extract_entities, write_entity_graph, embed_investigation |
| worker/entity_normalize.py | 131 | 1G | Entity normalization + hashing (IP, domain, hash, URL, email) |
| worker/redis_client.py | 44 | Block 1.3 | Redis connection helper |
| worker/model_config.py | 82 | 1I | 3-tier routing (fast/standard/reasoning) |
| worker/prompt_registry.py | 66 | 1I | SHA256[:12] prompt version tracking |
| worker/context_manager.py | 70 | 1I | Token-aware context truncation |
| worker/llm_logger.py | 83 | 1I | Non-blocking fire-and-forget LLM call logging |
| worker/prompt_init.py | 160 | 1I | Registers 10 prompts at startup |
| worker/rate_limiter.py | 129 | 1J | Lease-based rate limiting with Lua scripts |
| worker/shadow.py | — | Sprint 10 | Shadow mode workflow + 5 activities |
| worker/pii_detector.py | — | Sprint 10 | PII detection (9 regex patterns) + masking |
| worker/stampede.py | — | Sprint 10 | Anti-stampede (coalescing, probabilistic refresh, shard locks) |
| worker/token_quota.py | — | Sprint 10 | Per-tenant token quota + circuit breaker |
| worker/nats_consumer.py | — | Sprint 10 | NATS JetStream consumer (raw TCP) |
| worker/prompts/__init__.py | 1 | 1G | Package init |
| worker/prompts/entity_extraction.py | 59 | 1G | LLM prompt for structured entity extraction |
| worker/security/__init__.py | 0 | 1L | Package init |
| worker/security/injection_detector.py | 92 | 1L | Prompt injection detection (regex + heuristics) |
| worker/security/prompt_sanitizer.py | 31 | 1L | Untrusted data wrapping |
| worker/intelligence/__init__.py | 0 | 1L | Package init |
| worker/intelligence/blast_radius.py | 109 | 1L | Entity graph traversal for impact analysis |
| worker/intelligence/fp_analyzer.py | 230 | 1L | LLM-powered false positive confidence scoring |
| worker/intelligence/cross_tenant.py | 256 | 1K | Cross-tenant entity lookup + threat scoring |
| worker/intelligence/cross_tenant_workflow.py | 69 | 1K | CrossTenantRefreshWorkflow |
| worker/reporting/__init__.py | 0 | 1L | Package init |
| worker/reporting/incident_report.py | 284 | 1L | Markdown + PDF incident report generation |
| worker/skills/__init__.py | 0 | 1L | Package init |
| worker/skills/deobfuscation.py | 155 | 1L | Code deobfuscation activity |
| worker/bootstrap/__init__.py | 0 | 1F | Package init |
| worker/bootstrap/activities.py | 402 | 1F | MITRE/CISA loaders + synthetic investigation generator |
| worker/bootstrap/cisa_parser.py | 27 | 1F | CISA KEV JSON parser |
| worker/bootstrap/mitre_parser.py | 52 | 1F | MITRE ATT&CK parser |
| worker/bootstrap/workflow.py | 133 | 1F | BootstrapCorpusWorkflow |
| worker/detection/__init__.py | 0 | 2A | Package init |
| worker/detection/pattern_miner.py | 155 | 2A | Attack pattern mining from entity observations |
| worker/detection/sigma_generator.py | 209 | 2A | LLM-powered Sigma rule generation |
| worker/detection/rule_validator.py | 246 | 2A | TP/FP validation + auto-approval |
| worker/detection/workflow.py | 109 | 2A | DetectionGenerationWorkflow |
| worker/response/__init__.py | 0 | 2B | Package init |
| worker/response/actions.py | 242 | 2B | 7 SOAR action classes + webhook integration |
| worker/response/workflow.py | 305 | 2B | ResponsePlaybookWorkflow + approval gates |

### API Go Files (27 .go files, ~58 endpoints)

| File | Sprint | Purpose |
|------|--------|---------|
| api/shadow.go | Sprint 10 | Shadow mode endpoints |
| api/killswitch.go | Sprint 10 | Kill switch endpoints |
| api/tokenquota.go | Sprint 10 | Token quota endpoints + middleware |
| api/nats.go | Sprint 10 | NATS publisher (raw TCP) |
| api/oidc.go | Sprint 9 | OIDC SSO with JWKS verification |
| api/auth.go | Sprint 9 | Login, register, refresh, logout (httpOnly cookies) |

### Non-Worker Files

| File | Sprint | Purpose |
|------|--------|---------|
| monitoring/temporal_exporter.py | 1J | Temporal queue depth Prometheus exporter (port 9092) |
| monitoring/prometheus.yml | 1J | Prometheus scrape config |
| scripts/autoscale.py | 1J | Docker Compose autoscaler |
| scripts/seed_playbooks.py | 2B | Seeds 5 default SOAR playbooks |
| scripts/load_test.py | Block 1.4a | Load testing script |

### Migrations (32 files)

| File | Sprint |
|------|--------|
| 001_sprint1g_entity_graph.sql | 1G |
| 002_schema_drift_fixes.sql | 1E |
| 003_sprint1e_hardening.sql | 1E |
| 004_sprint1f_bootstrap.sql | 1F |
| 005_sprint1l_golden_path.sql | 1L |
| 006_sprint1k_cross_tenant.sql | 1K |
| 007_sprint1i_model_tiering.sql | 1I |
| 008_sprint2a_detection_engine.sql | 2A |
| 009_sprint2b_soar_playbooks.sql | 2B |
| 010_sprint3c_tenant_webhooks.sql | 3C |
| 011_sprint3d_finetuning.sql | 3D |
| 012_sprint3e_model_registry.sql | 3E |
| 013_sprint3f_security.sql | 3F |
| 014_sprint4a_sre_agent.sql | 4A |
| 015_sprint5_seed_skills_and_validation.sql | Sprint 5 |
| 016_alert_fingerprints.sql | Sprint 5 |
| 017_investigation_feedback.sql | Sprint 7 |
| 018_cost_tracking.sql | Sprint 7 |
| 019_investigation_cache.sql | Sprint 7 |
| 020_failure_context.sql | Sprint 9 |
| 021_hnsw_indexes.sql | Sprint 9 |
| 022_api_keys.sql | Sprint 9 |
| 023_totp.sql | Sprint 9 |
| 024_scheduled_workflows.sql | Sprint 9 |
| 025_incidents.sql | Sprint 9 |
| 026_sla_events.sql | Sprint 9 |
| 027_shadow_mode.sql | Sprint 10 |
| 028_token_quotas.sql | Sprint 10 |
| 029_kill_switch.sql | Sprint 10 |
| 030_pii_detection.sql | Sprint 10 |
| 031_nats_streams.sql | Sprint 10 |
| 032_stampede_protection.sql | Sprint 10 |

### Kubernetes Manifests

| Overlay | Resources |
|---------|-----------|
| base/ | api, dashboard, litellm, pgbouncer, postgres, redis, temporal, worker, namespace, secrets, kustomization |
| production/ | keda-scaledobject.yaml, kustomization.yaml |
| dev/ | kustomization.yaml |
| airgap/ | keda-scaledobject.yaml, kustomization.yaml |

---

## D. Data Summary

### Entity Graph
- **304 entities** across 8 types: domain (77), file_hash (62), process (61), ip (35), device (30), user (22), url (14), email (3)
- **258 edges** across 9 types: communicates_with (99), executed (42), logged_into (23), resolved_to (19), associated_with (19), downloaded (17), accessed (13), parent_of (13), contains (13)
- **588 observations** linking entities to investigations
- **3 tenants**: Zovark Dev (240 entities), Shield MSSP (32), Acme Security (32)

### Investigations
- **138 total**: 124 true_positive (avg risk 84), 14 suspicious (avg risk 68)
- **Sources**: 133 bootstrap (130 embedded), 5 production (4 embedded)
- **134/138 (97%) have summary embeddings** (768-dim vectors)

### Cross-Tenant Intelligence
- **29 entities** seen by 2+ tenants
- **13 entities** seen by all 3 tenants (ip, domain, file_hash, process, device, user)

### Threat Scores
- **71 entities** have threat scores > 0
- Highest average: ip (88), file_hash (86), device (83), process (80), user (80), domain (79)

### Knowledge Base
- **691 MITRE ATT&CK techniques** (all 691 embedded)
- **1,636 bootstrap corpus entries** (1,536 CISA KEV pending, 100 MITRE completed)

### Detection Engine
- **14 detection candidates** — all approved
- **14 Sigma rules** — all active, 12/14 with 100% TP rate, 0% FP rate
- Top techniques: T1059.001 (PowerShell, 7 investigations), T1003 (Credential Dumping, 4), T1078 (Valid Accounts, 3)

### SOAR Response
- **5 playbooks**: Brute Force, Ransomware, C2, Lateral Movement, Phishing
- **2 test executions** — both completed (4 actions each)
- **4/5 require approval**, Phishing Auto-Response runs without approval

### LLM Call Log
- **16 logged calls**: 14 generate_sigma_rule (reasoning tier, avg 2.5s), 2 generate_code (standard tier, avg 26s)
- **19,313 total tokens** tracked

### Reports
- **4 investigation reports**: 2 markdown (avg 2,388 chars), 2 PDF

### Audit Trail
- **21 audit events**: code_executed (6), investigation_started (6), investigation_completed (3), approval_requested (2), entity_extracted (2), approval_granted (2)

---

## E. Capability Matrix

| Capability | Sprint | Status | Evidence |
|------------|--------|--------|----------|
| Receive alerts via API (Go gateway) | Baseline | Working | API returns 401 on invalid token (auth enforced) |
| Generate investigation code via LLM | Baseline | Working | 10 completed tasks, LiteLLM healthy |
| Execute in sandboxed Docker | Baseline | Working | AST prefilter + seccomp + network=none + 30s kill timer |
| Multi-step investigation workflows | Baseline | Working | Temporal workflows with follow-up code generation |
| Approval gates for high-risk actions | Baseline | Working | 6 approval requests, signal-based Temporal workflow |
| Multi-worker scaling | Block 1.2 | Working | docker compose --scale worker=N |
| PgBouncer connection pooling | Block 1.3 | Working | Healthy, routing through port 5432 |
| Redis rate limiting (lease-based) | 1J | Working | Acquire/heartbeat/release verified |
| Kubernetes deployment manifests | Block 1.4b | Ready | Kustomize validated, 3 overlays (dev/prod/airgap) |
| KEDA autoscaling (K8s) | 1J | Ready | ScaledObject for production + airgap |
| Docker Compose autoscaling | 1J | Ready | scripts/autoscale.py + compose override |
| Temporal queue depth monitoring | 1J | Ready | Prometheus exporter on port 9092 |
| Sandbox hardening | 1E | Working | SCRAM-SHA-256, sync commit tuning, audit events |
| MITRE ATT&CK knowledge base | 1F | Working | 691 techniques, all embedded |
| CISA KEV vulnerability catalog | 1F | Loaded | 1,536 entries loaded |
| Synthetic investigation bootstrap | 1F/1H | Working | 100 synthetic investigations generated |
| Entity extraction (LLM-powered) | 1G | Working | 304 entities, 258 edges extracted |
| Entity normalization + hashing | 1G | Working | IP leading zeros fixed, defang handling |
| Entity graph (pgvector + cosine search) | 1G | Working | 768-dim embeddings, ivfflat index |
| Cross-tenant entity correlation | 1K | Working | 29 entities correlated across 3 tenants |
| Threat scoring | 1K | Working | 71 entities scored, avg 80+ for IOCs |
| Privacy-safe intelligence views | 1K | Working | cross_tenant_public strips tenant_ids |
| Blast radius computation | 1L | Working | Graph traversal with time window + hop limit |
| False positive confidence scoring | 1L | Working | LLM-powered analysis with cross-tenant context |
| Injection detection | 1L | Working | Clean/suspicious/injection_detected classification |
| Prompt sanitization | 1L | Working | Untrusted data wrapping |
| Code deobfuscation | 1L | Working | skills/deobfuscation.py activity |
| Incident report generation (MD + PDF) | 1L | Working | 4 reports generated (2 markdown, 2 PDF) |
| Model tiering (fast/standard/reasoning) | 1I | Working | 9 activities mapped to 3 tiers |
| Prompt version tracking | 1I | Working | 10 prompts registered with SHA256 versions |
| LLM call logging with cost tracking | 1I | Working | 16 calls logged, tokens + latency tracked |
| Context-aware truncation | 1I | Working | Token estimation + head/tail truncation |
| Sigma rule generation from patterns | 2A | Working | 14 rules generated from investigation patterns |
| Pattern mining from entity observations | 2A | Working | 14 patterns mined across MITRE techniques |
| Rule validation (TP/FP testing) | 2A | Working | 14/14 approved, 12 with 100% TP |
| SOAR playbook execution | 2B | Working | 2 test executions, both completed |
| Approval gates for destructive actions | 2B | Working | Brute Force Response tested with approval signal |
| Auto-trigger from investigation verdicts | 2B | Working | find_matching_playbooks + child workflow |
| 7 simulated response action types | 2B | Working | BlockIP, DisableUser, IsolateEndpoint, RotateCredentials, CreateTicket, SendNotification, QuarantineFile |
| Webhook integration path | 2B | Ready | response_integrations table, _call_webhook() implemented |
| Rollback on action failure | 2B | Working | Reversed action chain in workflow |
| CI/CD pipeline | 3A | Working | GitHub Actions: lint, test-imports, validate-migrations, build |
| Health endpoint + structured logging | 3A | Working | /health v1.0.0, JSON structured logs |
| Prometheus + Grafana observability | 3B | Working | 3 dashboards, 6 alert rules, postgres/redis exporters |
| Tenant CRUD API + webhooks | 3C | Working | Tenant management endpoints + per-tenant rate limits |
| Fine-tuning data pipeline | 3D | Working | Training export, quality scoring, model evaluation |
| Model registry + A/B testing | 3E | Working | Dynamic routing with A/B experiment support |
| Security hardening (audit, lockout) | 3F | Working | Audit middleware, auth rate limiting, account lockout, data retention |
| Self-healing SRE agent | 4A | Working | Failure scan, diagnosis, patching, testing, application (dry-run default) |
| MCP server | 4C | Working | 7 tools, 7 resources, 6 prompts (TypeScript) |
| Multi-provider LLM fallback | Sprint 5 | Working | Groq, OpenRouter, Anthropic, OpenAI, Ollama airgap |
| Investigation dashboard | Sprint 6 | Working | Waterfall visualization + C2 beacon demo mode |
| Shadow Mode | Sprint 10 | Working | NATS JetStream, PII detection, token quotas, kill switch, anti-stampede |
| OIDC SSO + JWKS verification | v0.10.1 | Working | ID tokens verified against provider JWKS (RSA) |
| httpOnly cookie auth | v0.10.1 | Working | Access token in memory, refresh in httpOnly cookie |

---

## F. Known Issues / Tech Debt

### Issues

1. **No local LLM inference** — LiteLLM is configured with OpenRouter (cloud) instead of local vLLM. The `litellm_config.yaml` routes "fast" to `openrouter/google/gemini-2.0-flash-001`. Local vLLM instances are not running (no GPU container in compose services).

2. **CISA KEV corpus not processed** — 1,536 CISA entries loaded but all in `pending` status. Only MITRE-sourced entries (100) have been processed into synthetic investigations.

3. **agent_skills table empty** — No skills have been registered in the database. Skill retrieval falls back to vector similarity search.

4. **agent_task_steps empty** — The `agent_task_steps` table has 0 rows despite 10 tasks; steps are tracked in `investigation_steps` (16 rows) instead.

5. **context_manager export mismatch** — The module exports `truncate_for_model` but some references expect `prepare_context`. Minor naming inconsistency.

6. **All models route to "fast" tier** — Model tiering maps activities to tiers (fast/standard/reasoning) but the actual model name resolves to "fast" for all since only one chat model is configured in LiteLLM.

7. **response_playbooks missing idx_playbooks_tenant index** — The `\d response_playbooks` output shows only `idx_playbooks_enabled` but not `idx_playbooks_tenant`. The CREATE INDEX ran but may have been applied to a previous duplicate.

8. **Legacy tables present** — `playbooks`, `agent_audit_log`, `agent_personas`, `agent_memory_episodic`, `working_memory_snapshots`, `object_refs` exist but appear unused by current code.

### Tech Debt

1. **Credentials in plaintext** — `response_integrations.auth_credentials` stored as TEXT. Migration has TODO comment: "migrate to Vault for production."

2. **No migration runner** — Migrations are applied manually via `psql`. No versioning table or migration tool (Flyway, Alembic, etc.).

3. **Playbook trigger templates** — Playbook action contexts use `{{attacker_ip}}` style placeholders that are not resolved at execution time; they pass through as literal strings.

4. **Single-tenant rate limiting** — Lease limits are per-tenant but the global limit (default 10) may not be appropriate for all deployment sizes.

5. **No embedding model hot-reload** — TEI (text-embeddings-inference) container uses a fixed model. Switching embedding models requires container rebuild.

---

## G. Phase 2 Recommendations

### Revenue-Critical (Build First)

1. ~~**Dashboard + Analytics UI**~~ — DONE (Sprint 6 + Sprint 9). React dashboard with 15 pages: investigation timeline, entity graph visualization, playbook builder, SIEM alerts, admin panel, cost tracking, dark/light mode.

2. ~~**Real Webhook Integrations**~~ — DONE (Sprint 3C). Tenant webhook endpoints with per-tenant rate limits and CRUD API.

3. ~~**Multi-Tenant Onboarding**~~ — DONE (Sprint 3C). Tenant CRUD API with self-service creation, API key management (Sprint 9), per-tenant rate limits.

4. ~~**SIEM Connector Library**~~ — DONE (Sprint 9). SIEM alert ingestion endpoints with correlation engine and batch processing.

### Platform Hardening

5. ~~**CI/CD Pipeline**~~ — DONE (Sprint 3A). GitHub Actions: lint, test-imports, validate-migrations, build. All checks green.

6. **Vault Integration** — Move `auth_credentials`, `JWT_SECRET`, `LITELLM_MASTER_KEY` to HashiCorp Vault. Critical for enterprise sales.

7. **Local LLM Restoration** — Restore vLLM containers for air-gapped deployments. The K8s airgap overlay expects local inference. Ollama fallback exists (Sprint 5) but vLLM containers are not in compose.

8. **Playbook Template Resolution** — Wire `{{attacker_ip}}` style variables to actual investigation output fields at trigger time.

### Scale & Intelligence

9. **Process CISA KEV Corpus** — Run bootstrap workflow on the 1,536 pending CISA entries to expand the investigation corpus for better detection and similarity matching.

10. **Detection Rule Deployment** — Export approved Sigma rules to SIEM platforms. Add rule lifecycle management (testing, deployment, retirement).

11. **Feedback Loop** — Analyst feedback on investigations (confirm/reject verdict) feeds back into FP model training and detection rule tuning. Feedback endpoint exists (Sprint 7); needs closed-loop integration.

12. **Scheduled Workflows** — Periodic cross-tenant intel refresh, detection rule regeneration, and corpus expansion via Temporal cron schedules. Scheduling infrastructure exists (Sprint 9 migration 024); needs workflow wiring.

---

## Infrastructure Summary

| Component | Version | Status |
|-----------|---------|--------|
| PostgreSQL + pgvector | 16 | Healthy |
| Redis | 7-alpine | Healthy (256MB LRU) |
| PgBouncer | latest | Healthy |
| NATS | 2.10-alpine | Running (JetStream, 100k/sec alert buffering) |
| Temporal | 1.24.2 | Running |
| LiteLLM | main-stable | Healthy |
| TEI (embeddings) | cpu-1.2 | Running (768-dim) |
| Go API | custom | Running (port 8090, 27 .go files, ~58 endpoints) |
| React Dashboard | custom | Running (port 3000, 15 pages) |
| Worker (Python) | custom | Healthy (39+ files, 10 workflows, 95 activities) |
| Prometheus | latest | Running (port 9090) |
| Grafana | latest | Running (port 3001, 3 dashboards) |
| MCP Server | custom | Running (TypeScript, 7 tools, 7 resources, 6 prompts) |

**Total Docker disk usage:** 14.5 GB images, 607 MB container data, 121 MB volumes

---

*Generated by ZOVARK Final Audit — 2026-03-14*
