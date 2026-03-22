# Changelog

## v1.2.0 — 2026-03-22 — Enterprise-Grade Pipeline

### Pipeline Reliability
- Race condition: `ExecuteWorkflow` moved after `tx.Commit()` in all 3 code paths (root cause fix)
- Schema validation: all output validated with safe default on failure, logged to `llm_audit_log`
- JWT auto-refresh: benchmark runner handles token expiry gracefully (refresh every 10 submissions + 401 retry)

### Enterprise Features
- MITRE ATT&CK: technique mapping for all 11 investigation types (`worker/stages/mitre_mapping.py`)
- IOC confidence scores: high/medium/low based on extraction method
- Investigation metadata: pipeline version, schema validation status in every output
- Metrics endpoint: `GET /api/v1/metrics` with investigation stats, LLM performance, template health
- Seccomp profile: kernel-level syscall restriction documented (`docs/SANDBOX_SECURITY.md`)

### Skill Templates
- All 11 templates producing valid structured output (was 5/11)
- IOC format: converted from dict to list-of-dicts with type/value/severity/confidence
- Consistent schema: findings, iocs, risk_score, verdict, recommendations

### Dashboard
- MITRE ATT&CK section: clickable technique badges linked to attack.mitre.org
- IOC confidence badges: high (red), medium (yellow), low (gray)

### Documentation
- Technical whitepaper: "Autonomous SOC Investigation on Air-Gapped Infrastructure" (`docs/WHITEPAPER.md`)
- Conference submissions: BlackHat Arsenal, DEF CON Demo Labs, BSides LV (`docs/CONFERENCE_SUBMISSIONS.md`)
- Architecture diagram: full pipeline Mermaid visualization, air-gap boundary (`docs/ARCHITECTURE.md`)
- Sandbox security documentation (`docs/SANDBOX_SECURITY.md`)

---

## v1.1.0 — 2026-03-22 — Demo-Ready Release

### Pipeline
- V2 pipeline: 5/5 investigation types completing with real findings
- LLM audit gateway: all LLM calls logged to `llm_audit_log` table
- Model routing: severity-based model selection via `model_config.yaml`
- Sandbox policy: declarative YAML configuration (`sandbox_policy.yaml`)
- LLM timeout fix: 30s → 120s for RTX 3050 single-slot queueing
- All 11 skill templates producing valid investigation output

### Dashboard
- 15-page React 19 + Vite 7 + Tailwind 4 dark-mode dashboard
- Live polling: 5s alert queue, 2s investigation detail
- Investigation detail: verdict, risk score, IOCs, findings, pipeline timeline
- Auth: JWT in sessionStorage, httpOnly refresh cookies, CORS configured
- API proxy via Vite dev server and nginx production config

### Benchmarking
- 200-alert synthetic benchmark corpus with ground-truth labels
- 100-alert OWASP Juice Shop real-traffic benchmark corpus
- Automated scoring with per-attack-type accuracy breakdown
- Nemotron 3 Nano 4B benchmark scripts (model download pending)

### Security
- Credentials removed from documentation (env var references)
- Dead services removed from docker-compose (NATS, LiteLLM, TEI → optional)
- Temporal stale workflow cleanup script

### Deployment
- Production Docker Compose with 8 core services
- Install/health/backup/demo shell scripts in `deploy/`
- Dashboard served via nginx in Docker
- Windows startup script (`scripts/start_hydra.bat`)
- Hardware tier documentation
- SIEM integration guide (Splunk, Elastic, Sentinel)

### Documentation
- Updated CLAUDE.md to v1.1.0
- Demo script for 2-minute CISO presentation
- Landing page copy with positioning and CTA

### 67 commits since v1.0.0-rc1

## v0.18.0 — Documentation + Polish
- Updated ARCHITECTURE.md with full feature coverage through v0.17.0
- CHANGELOG documenting all versions from v0.10.1 to v0.18.0
- PoV section linking to scripts/pov/README.md

## v0.17.0 — 48-Hour PoV Package
- SIEM import script (Splunk CSV, Sentinel JSON, QRadar XML, generic JSON)
- Comparison report generator (Markdown + HTML, MTTR/ROI calculation)
- One-command deployment script (secret generation, stack startup, migrations)
- PoV playbook (Day 1 deploy + historical analysis, Day 2 live + results)

## v0.16.0 — Deployment Hardening
- Configurable CORS origins (`HYDRA_CORS_ORIGINS` env var)
- vLLM containers restored (opt-in `--profile vllm`)
- OpenAPI spec refreshed to v1.2.0 (9 new endpoints)
- Legacy table cleanup (4 unused tables dropped)
- K8s manifest validation script (dry-run for all overlays)

## v0.15.0 — Architectural Fixes + Operational Readiness
- **5 architectural fixes:**
  - CI `|| true` gates removed (lint/test/pytest now fail-fast)
  - DB connection pooling wired (psycopg2 ThreadedConnectionPool, 3 tiers)
  - 4 dead workflows + 3 dead activities registered (16 workflows, 104 activities)
  - Raw TCP Redis replaced with go-redis/v9 (pooled client, pipeline rate limiting)
  - 1275-line handlers.go split into 6 domain files
- **3 operational features:**
  - Playbook template variable resolution (14 variables, injection-safe)
  - Analyst feedback loop (FP signal, rule accuracy, daily aggregation workflow)
  - CISA KEV corpus processing (batch workflow, alert generator, migration 038)

## v0.14.0 — Testing + CI + Migration Runner
- 41 Go unit tests (auth, tenant isolation, RBAC, rate limiting, headers, errors)
- 90+ Python tests (AST prefilter, risk validator, sanitizer, adversarial, vault, egress)
- E2E integration tests (full investigation flow, security validation)
- Load test baseline (15 inv/min gate)
- Migration runner (golang-migrate, advisory lock, up/down/version/force)
- CI pipeline (GitHub Actions: lint, test-imports, validate-migrations, go-tests, python-tests, build, integration)

## v0.13.0 — Analytics + ML Detection + Network Analysis
- DB performance indexes (12 indexes across key tables)
- Connection pool manager (3 tiers: critical/normal/background)
- Read replica router
- DeepLog LSTM anomaly detection (PyTorch model + statistical fallback)
- StringSifter binary analysis
- Attack surface recon (Temporal activity)
- Zeek log ingestion (network analysis workflow)
- WebSocket collaboration (real-time investigation sharing)
- 4 new Temporal workflows, env config management

## v0.12.0 — Defense-in-Depth Hardening
- Vault JIT token system (HashiCorp Vault integration)
- Egress proxy (Squid + domain allowlist)
- Alert sanitization (5-stage pipeline)
- Adversarial model review (red-team LLM code review)
- MCP approval gate (human-in-the-loop for workflow execution)

## v0.11.0 — Security Remediation (P1+P2)
- 18 P1+P2 security fixes (completing all 30/30 audit items)
- Tenant isolation on models, A/B tests, retention policies
- AST prefilter v2 (40+ blocked modules)
- `wrap_untrusted_data` coverage (all LLM callsites)
- Error message sanitization (66 callsites)
- Rate limit fail-closed behavior
- TLS config, risk score validation, deobfuscation injection fix
- json.Marshal for audit logs, TOTP encryption, Redis/NATS auth
- Data retention job, CSP/HSTS headers, RLS, GDPR erasure
- Encrypted backups, sandbox `--user` flag

## v0.10.2 — Security (P0 Batch 2)
- 8 P0 fixes: injection blocking, PII masking wiring, tenant validation
- Body size limits, cache tenant isolation, tenant CRUD scoping
- Docker sandbox dry-run, SIEM prompt sanitization

## v0.10.1 — Critical Security Fixes
- Close exposed ports (only API 8090 + Dashboard 3000 host-accessible)
- Strong JWT secret requirement (min 32 chars, fatal on startup)
- JWT expiration enforced (15 min access, 7 day refresh, httpOnly cookies)
- OIDC JWKS verification (RSA, auto-refresh)
- httpOnly cookies (access token in memory, refresh in httpOnly+SameSite=Strict)

## v0.10.0 — Shadow Mode
- Shadow mode investigation workflow (safety-first automation)
- NATS JetStream alert buffering (100k/sec)
- PII detection + masking (9 regex patterns)
- Per-tenant token quotas + circuit breaker
- Kill switch (emergency automation pause)
- Anti-stampede protection (coalescing, probabilistic refresh)

## v0.9.0 — 55 GitHub Issues
- Go API: OIDC, API keys, TOTP 2FA, SLA monitoring
- Python worker: correlation engine, scheduled workflows, batch embedding
- React dashboard: 6 pages (investigations, SIEM, approvals, settings, admin, entity graph)
- Testing and deployment foundations
