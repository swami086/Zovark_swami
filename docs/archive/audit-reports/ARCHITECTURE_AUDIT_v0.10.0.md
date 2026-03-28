# ZOVARK v0.10.0 — Architecture Audit Report

**Date:** 2026-03-13
**Audited by:** Claude Opus 4.6
**Scope:** Full-stack audit — Go API, Python Worker, Database, Dashboard, MCP Server, Docker, Security, Observability

---

## Executive Summary

| Layer | Files | LOC | Status |
|-------|-------|-----|--------|
| Go API | 27 .go files | ~7,319 | Functional, security gaps |
| Python Worker | 91 .py files | ~6,153 | Solid, minor issues |
| Database | 56 tables, 32 migrations | ~1,500 SQL | Well-structured |
| Dashboard | 33 .tsx/.ts files | ~4,200 | Functional, no tests |
| MCP Server | 4 .ts files | ~1,200 | Clean |
| Docker | 20 services | — | Over-exposed ports |

---

## 1. COMPONENT INVENTORY

### Go API — 56 endpoints across 27 files

| Group | Count | Key Handlers |
|-------|-------|-------------|
| Public | 2 | `/health`, `POST /webhooks/:source_id/alert` (HMAC) |
| Auth | 4 | login, register, SSO login, SSO callback |
| Tasks | 8 | CRUD, bulk, upload, steps, timeline, stream |
| Shadow Mode | 5 | recommendations, decide, conformance, status |
| Kill Switch | 5 | controls, kill, resume, audit |
| Token Quotas | 4 | quota status, update, circuit breaker, usage |
| SIEM | 4 | alerts, log sources, investigate |
| Approvals | 2 | pending, decide |
| Tenants | 4 | CRUD |
| Webhooks | 4 | endpoints, deliveries |
| Models | 5 | registry, A/B tests |
| Integrations | 4 | Slack, Teams |
| Auth extras | 5 | TOTP, API keys |
| Other | 4 | stats, skills, playbooks, notifications |

### Python Worker — 10 workflows, 95 activities

| Module | Activities | New in v0.10.0 |
|--------|-----------|----------------|
| Core investigation | 14 | — |
| Skills & memory | 6 | — |
| Entity graph | 4 | — |
| Bootstrap corpus | 5 | — |
| Intelligence | 9 | — |
| Detection engine | 4 | — |
| Response playbooks | 7 | — |
| Fine-tuning | 6 | — |
| SRE self-healing | 5 | — |
| Scheduling/correlation | 6 | — |
| Integrations | 7 | — |
| Embedding | 4 | — |
| **Shadow mode** | **5** | generate_recommendation, check_automation_mode, record_human_decision, compute_conformance_metrics, check_mode_graduation |
| **PII detection** | **4** | detect_pii, mask_for_llm, unmask_response, load_tenant_pii_rules |
| **Anti-stampede** | **2** | coalesced_llm_call, check_stampede_protection |
| **Token quotas** | **4** | check_token_quota, record_token_usage, reset_monthly_quota, trip_circuit_breaker |

### Database — 56 tables, 95+ indexes, 6 views, 2 triggers

- Partitioned tables: `investigations` (13 monthly), `audit_events` (13 monthly)
- Vector indexes: 5 HNSW/IVFFlat (768-dim embeddings)
- Schema version: 1.3.0

### Dashboard — 15 pages, 11 components, 2 hooks

Dependencies: React 19, Vite 7, Tailwind 4, TypeScript 5.9, Lucide icons, date-fns — all current versions.

---

## 2. DEPENDENCY VALIDATION

### Go (go.mod) — 7 direct dependencies

| Package | Current | Latest | Status |
|---------|---------|--------|--------|
| gin | v1.9.1 | v1.10.0 | YELLOW — Outdated (2023) |
| pgx | v5.5.3 | v5.7.0 | YELLOW — Outdated |
| golang.org/x/crypto | v0.21.0 | v0.31.0 | YELLOW — Update recommended |
| temporal/sdk | v1.25.1 | v1.27.0 | YELLOW — Outdated |
| golang-jwt/jwt | v5.3.1 | Current | GREEN |
| google/uuid | v1.6.0 | Current | GREEN |
| gin-contrib/cors | v1.5.0 | Current | GREEN |

### Python (requirements.txt) — 8 deps, ALL UNPINNED

| Package | Pinned? | Risk |
|---------|---------|------|
| temporalio | No | RED — Pin version |
| litellm | No | RED — Pin version |
| psycopg2-binary | No | YELLOW — Pin |
| redis | No | YELLOW — Pin |
| httpx | No | YELLOW — Pin |
| reportlab | No | YELLOW — Pin |
| pyyaml | No | YELLOW — Pin |
| pytest | No | YELLOW — Dev only |

### Dashboard (package.json) — All current

GREEN — React 19.2.0, Vite 7.3.1, Tailwind 4.2.1, TypeScript 5.9.3 — no vulnerabilities detected.

### MCP Server (package.json)

GREEN — @modelcontextprotocol/sdk 1.12.1, pg 8.13.1 — current.

---

## 3. SECURITY SCAN

### RED — CRITICAL (5)

| # | Issue | Location | Impact |
|---|-------|----------|--------|
| 1 | **JWT stored in localStorage** | `dashboard/src/api/client.ts:3` | XSS can steal auth tokens |
| 2 | **Expired JWT tokens accepted** | `api/middleware.go:57-58` | Session fixation via old tokens |
| 3 | **OIDC ID token signature not verified** | `api/oidc.go:201,323` | Token substitution attack |
| 4 | **PostgreSQL port 5432 exposed to host** | `docker-compose.yml` | Direct DB access from network |
| 5 | **Redis port 6379 exposed, no auth** | `docker-compose.yml` | Unprotected cache access |

### YELLOW — HIGH (6)

| # | Issue | Location |
|---|-------|----------|
| 6 | Temporal 7233 exposed to host, no auth | `docker-compose.yml` |
| 7 | NATS 4222 exposed, no auth token | `docker-compose.yml` |
| 8 | Hardcoded JWT secret `zovark-jwt-secret-dev-2026` (27 chars) | `api/main.go:43` |
| 9 | Rate limiting fails open on Redis error | `api/ratelimit.go:157-161` |
| 10 | Audit logs fire async (may not persist on crash) | `api/security.go:108` |
| 11 | Unvalidated pip package names in SRE applier | `worker/sre/applier.py:215` |

### YELLOW — MEDIUM (5)

| # | Issue | Location |
|---|-------|----------|
| 12 | `sslmode=disable` for all DB connections | `docker-compose.yml` |
| 13 | No CSP headers configured | API + Dashboard |
| 14 | Health check HTTP client has no timeout | `api/handlers.go` |
| 15 | Docker socket mounted in worker | `docker-compose.yml` (acceptable for sandbox) |
| 16 | Single bridge network — no service isolation | `docker-compose.yml` |

### GREEN — GOOD (8)

- All SQL queries parameterized ($1/$2 in Go, %s in Python) — no injection risk
- bcrypt password hashing (cost=10)
- API key hashing (SHA-256, raw shown once)
- HMAC-SHA256 webhook validation (inbound + outbound)
- CORS restricted to `localhost:3000`
- No `eval()`, `exec()`, `pickle.loads()` in worker
- PII regex patterns safe (no ReDoS)
- Sandbox: 5-layer defense (AST + seccomp + network=none + resource limits + kill timer)

---

## 4. CONFIGURATION AUDIT

### Environment Variables (14 in Config struct)

| Variable | Default | Risk |
|----------|---------|------|
| `DATABASE_URL` | `postgresql://zovark:zovark_dev_2026@...` | YELLOW — Dev creds |
| `JWT_SECRET` | `zovark-jwt-secret-dev-2026` | RED — Weak |
| `LITELLM_MASTER_KEY` | `sk-zovark-dev-2026` | YELLOW — Dev key |
| `NATS_URL` | (empty — optional) | GREEN — Graceful fallback |
| `REDIS_URL` | `redis:6379` | GREEN |
| `TEMPORAL_ADDRESS` | `temporal:7233` | GREEN |
| `PORT` | `8090` | GREEN |
| `VAULT_ADDR/TOKEN` | (empty — optional) | GREEN |
| `OIDC_*` | (empty — optional) | GREEN |

### Exposed Ports (Production risk)

| Port | Service | Should be exposed? |
|------|---------|-------------------|
| 3000 | Dashboard | GREEN — Yes |
| 8090 | API | GREEN — Yes |
| 5432 | PostgreSQL | RED — **No** |
| 6379 | Redis | RED — **No** |
| 7233 | Temporal | RED — **No** |
| 4222 | NATS | RED — **No** |
| 4000 | LiteLLM | YELLOW — Internal only |
| 8081 | Embedding | YELLOW — Internal only |
| 9000-9001 | MinIO | YELLOW — Profile-gated |
| 3001, 9090 | Grafana, Prometheus | YELLOW — Profile-gated |

---

## 5. OBSERVABILITY ASSESSMENT

| Area | Status | Detail |
|------|--------|--------|
| Prometheus metrics | YELLOW | 5 scrape targets, LiteLLM missing |
| Alert rules | GREEN | 6 rules — pending tasks, failure rate, connections, memory, workers, latency |
| Grafana dashboards | GREEN | 3 dashboards |
| Structured logging (API) | RED | Uses `log.Printf` (not JSON) |
| Structured logging (Worker) | GREEN | JSON logger to stderr |
| Distributed tracing | RED | Jaeger configured but no OTLP instrumentation |
| Client-side metrics | RED | No React instrumentation |
| Per-activity latency | RED | No histogram buckets |

---

## 6. TESTING GAPS

| Component | Test Files | Coverage | Status |
|-----------|-----------|----------|--------|
| Sandbox security | 5 files | High | GREEN — Comprehensive |
| E2E flows | 3 files | Medium | YELLOW — Auth, tenant isolation, full flow |
| Worker activities | 15+ files | Medium | YELLOW — Missing approval/retry tests |
| Threat corpus | 20 scenarios | High | GREEN — 5 categories x 4 levels |
| Accuracy validation | 50 labeled alerts | Medium | YELLOW |
| **Dashboard** | **0 files** | **None** | **RED — No component tests** |
| **MCP Server** | **0 files** | **None** | **RED — No tool tests** |
| **Go API unit** | **0 files** | **None** | **RED — No handler unit tests** |
| **v0.10.0 features** | **0 files** | **None** | **RED — Shadow/PII/quota untested** |

---

## 7. GAP ANALYSIS

### RED — Must Fix Before Production

1. **JWT in localStorage** — Migrate to httpOnly cookies
2. **Accept expired tokens** — Enforce token expiry validation
3. **OIDC signature skip** — Add JWKS validation
4. **Database/Redis/Temporal exposed** — Restrict to internal networks only
5. **Unpinned Python deps** — Pin all versions
6. **No structured logging in Go API** — Implement JSON logging
7. **No OTEL tracing** — Add spans to API + worker

### YELLOW — Should Fix Before Beta

1. **Outdated Go deps** — Update gin, pgx, crypto, temporal
2. **No dashboard tests** — Add Vitest + React Testing Library
3. **No Go API unit tests** — Add table-driven tests
4. **No v0.10.0 tests** — Test shadow mode, PII, quotas, kill switch
5. **No backup scripts** — Implement pg_dump + WAL archiving
6. **Single Docker network** — Segment into 6 functional zones
7. **No CSP headers** — Add Content-Security-Policy
8. **No secret rotation procedure** — Document + automate
9. **Rate limit fail-open** — Add circuit breaker for Redis failure
10. **Health check no timeout** — Add 5s timeout to http.Get

### GREEN — Working Well

- Multi-tenant isolation (app-level query filtering)
- Sandbox security (5-layer defense-in-depth)
- SQL injection prevention (parameterized everywhere)
- PII detection patterns (safe regex, no ReDoS)
- Anti-stampede protections (atomic Redis locking)
- Token quota enforcement (atomic updates, circuit breaker)
- Shadow mode architecture (30-day graduation protocol)
- Kill switch (instantaneous, audit-logged)
- Disaster recovery documentation (RTO/RPO defined)
- SOAR playbooks + MITRE ATT&CK mapping
- MCP server (7 tools, 7 resources, read-only SQL enforcement)

---

## 8. RESOURCE ALLOCATION

### Docker Services — Total Resource Budget

```
RAM:  ~7.5 GB (postgres 2GB, litellm 1GB, embedding 1GB, temporal 512MB,
      worker 512MB, prometheus 512MB, grafana 256MB, api 256MB, nats 256MB,
      redis 128MB, pgbouncer 128MB, dashboard 128MB, caddy 128MB, others)

CPU:  ~4.5 cores (postgres 1.0, embedding 1.0, temporal 0.5, litellm 0.5,
      worker 0.5, prometheus 0.5, api 0.25, redis 0.25, pgbouncer 0.25,
      dashboard 0.25, caddy 0.25)

GPU:  0.55 of 4GB VRAM (chat 0.40 + embed 0.15) — RTX 3050
```

### Volumes (8 named)

```
postgres_data, redis_data, minio_data, nats-data,
ollama_data, prometheus_data, grafana_data, caddy_data/caddy_config
```

---

## 9. DETAILED SECURITY FINDINGS

### Go API Security

| Finding | Severity | File:Line | Detail |
|---------|----------|-----------|--------|
| Expired token bypass | CRITICAL | middleware.go:57 | `strings.Contains(err.Error(), "token is expired")` allows expired JWTs |
| OIDC no sig verify | CRITICAL | oidc.go:201 | ID token parsed without JWKS validation |
| JWT secret weak | HIGH | main.go:43 | Default: `zovark-jwt-secret-dev-2026` (27 chars) |
| Rate limit fail-open | HIGH | ratelimit.go:157 | `c.Next()` on Redis error |
| Async audit logs | HIGH | security.go:108 | `go func()` — may not persist on crash |
| No health timeout | MEDIUM | handlers.go | `http.Get()` with no timeout |
| Account lockout | LOW | security.go:148 | 5 attempts, 30min — acceptable |

### Python Worker Security

| Finding | Severity | File:Line | Detail |
|---------|----------|-----------|--------|
| pip install unvalidated | HIGH | sre/applier.py:215 | Package name not regex-validated |
| Hardcoded dev creds | MEDIUM | 40 files | `zovark_dev_2026` as defaults (env override exists) |
| Code scrubbing fragile | MEDIUM | activities.py:194 | Regex-based, bypassable (AST prefilter is real defense) |
| 24 print() statements | LOW | Various | Should use structured logger |
| Rate limiter TODO | LOW | rate_limiter.py:129 | Set membership O(N), needs sorted sets for >100 |

### Dashboard Security

| Finding | Severity | File:Line | Detail |
|---------|----------|-----------|--------|
| JWT in localStorage | CRITICAL | api/client.ts:3 | XSS-accessible, should use httpOnly cookies |
| Hardcoded API URL | MEDIUM | api/client.ts:1 | `http://localhost:8090` — use VITE env var |
| No CSP headers | MEDIUM | — | Content-Security-Policy not configured |
| No error boundary | MEDIUM | App.tsx | Unhandled rejections crash app silently |
| No dangerouslySetInnerHTML | GREEN | — | All user input auto-escaped by React |

---

## 10. DATABASE AUDIT

### Schema Statistics

| Metric | Count |
|--------|-------|
| Tables | 56 |
| Physical tables (incl. partitions) | ~78 |
| Indexes | 95+ |
| Materialized views | 3 |
| Regular views | 3 |
| Triggers | 2 (immutability on audit_log + usage_records) |
| GIN indexes (array columns) | 6 |
| Vector indexes (HNSW/IVFFlat) | 5 |
| Partial indexes | 5+ |

### Foreign Key Gap

3 tables reference `investigations(id)` without FK constraints (partitioned table limitation):
- `entity_edges.investigation_id`
- `entity_observations.investigation_id`
- `response_executions.investigation_id`

**Risk:** Dangling references possible. Requires application-level enforcement.

---

## 11. PRODUCTION READINESS SCORECARD

| Category | Score | Status |
|----------|-------|--------|
| Authentication | 6/10 | YELLOW — JWT storage, expired tokens |
| Authorization | 9/10 | GREEN — RBAC, tenant isolation |
| Encryption in transit | 3/10 | RED — sslmode=disable, no mTLS |
| Encryption at rest | 2/10 | RED — Not configured |
| Logging | 6/10 | YELLOW — Worker good, API not structured |
| Monitoring | 6/10 | YELLOW — Prometheus partial, no tracing |
| Backup/DR | 5/10 | YELLOW — Documented but no scripts |
| Testing | 4/10 | RED — No dashboard/API/MCP/v0.10.0 tests |
| Secrets management | 3/10 | RED — Hardcoded dev secrets |
| Input validation | 9/10 | GREEN — Parameterized SQL, typed inputs |
| API documentation | 8/10 | GREEN — OpenAPI spec exists |
| Multi-tenancy | 8/10 | GREEN — App-level isolation (no RLS) |
| **Overall** | **5.75/10** | **YELLOW — Functional pre-beta, not production-ready** |

---

## 12. RECOMMENDED ACTION PLAN

### Phase 1: Security Hardening (Week 1-2)

- [ ] Migrate JWT from localStorage to httpOnly cookies
- [ ] Enforce JWT expiry validation (remove MVP bypass)
- [ ] Add OIDC JWKS signature verification
- [ ] Restrict DB/Redis/Temporal/NATS ports to internal network
- [ ] Pin all Python dependencies
- [ ] Increase JWT secret to 32+ chars
- [ ] Add CSP headers to API responses

### Phase 2: Testing (Week 2-3)

- [ ] Add Vitest + React Testing Library for dashboard (50+ tests)
- [ ] Add Go table-driven unit tests for API handlers
- [ ] Add MCP tool tests with mock pg client
- [ ] Test v0.10.0 features: shadow mode, PII, quotas, kill switch
- [ ] Add integration test for NATS → worker → DB flow

### Phase 3: Observability (Week 3-4)

- [ ] Implement structured JSON logging in Go API
- [ ] Add OpenTelemetry tracing to Go + Python + React
- [ ] Add per-activity latency histograms
- [ ] Add LiteLLM scrape target to Prometheus
- [ ] Implement client-side error tracking

### Phase 4: Operations (Month 2)

- [ ] Implement pg_dump backup scripts + WAL archiving
- [ ] Segment Docker network into 6 zones
- [ ] Document and automate secret rotation
- [ ] Add rate limit circuit breaker for Redis failure
- [ ] Implement PostgreSQL row-level security (RLS)

---

**Bottom line:** The architecture is sound and feature-rich for a v0.10.0 pre-beta. The 5 critical security items (JWT storage, expired tokens, OIDC signatures, exposed infrastructure ports, unpinned deps) must be fixed before any external pilot. The testing gaps (dashboard, MCP, Go unit tests, v0.10.0 features) are the largest risk for regression as development accelerates toward v0.11.0.
