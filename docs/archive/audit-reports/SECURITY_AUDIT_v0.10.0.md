# ZOVARK v0.10.0 — Security Audit Report

**Date:** 2026-03-13
**Audited by:** Claude Opus 4.6 (6 parallel deep-dive scans)
**Scope:** Go API, Python Worker, Sandbox, Database, Docker, Dashboard, MCP Server
**Classification:** CONFIDENTIAL — Internal Use Only

---

## EXECUTIVE SUMMARY

| Audit | Critical | High | Medium | Low |
|-------|----------|------|--------|-----|
| 1. Vulnerability Scan | 5 | 11 | 4 | 0 |
| 2. Tenant Isolation | 7 | 5 | 4 | 1 |
| 3. Prompt Injection | 4 | 5 | 3 | 0 |
| 4. Sandbox Escape | 1 | 3 | 2 | 1 |
| 5. Data Protection | 4 | 3 | 2 | 0 |
| 6. API Security | 0 | 3 | 2 | 0 |
| **TOTAL** | **21** | **30** | **17** | **2** |

**Verdict: NOT PRODUCTION-READY. 21 critical findings must be resolved before any external pilot.**

**Stop conditions triggered:**
- Audit 1: 5 CRITICAL issues found (registration, JWT, OIDC, hardcoded secrets)
- Audit 3: 4 CRITICAL prompt injection paths found (SIEM data flows raw into LLM prompts)
- Audit 4: 1 CRITICAL sandbox finding (dry-run executes on worker host)

---

## AUDIT 1: CRITICAL VULNERABILITY SCAN

### CRITICAL (5)

**C1. Expired JWT tokens accepted as valid**
`api/middleware.go:57-62`
```go
if err != nil && !strings.Contains(err.Error(), "token is expired") {
```
Any JWT ever issued works indefinitely. Stolen tokens = permanent access.
**Fix:** Remove bypass. Implement token refresh flow. Gate behind `ALLOW_EXPIRED_TOKENS` env var for dev only.

**C2. Hardcoded JWT signing secret**
`api/main.go:43`
```go
JWTSecret: getEnvOrDefault("JWT_SECRET", "zovark-jwt-secret-dev-2026"),
```
Public default = anyone can forge admin JWTs.
**Fix:** Fail startup if `JWT_SECRET` not set. Require 256-bit random secret.

**C3. Hardcoded database credentials**
`api/main.go:40`
Default `postgresql://zovark:zovark_dev_2026@postgres:5432/zovark` in source code.
**Fix:** Require `DATABASE_URL` as mandatory. No defaults.

**C4. Open registration accepts any tenant_id**
`api/auth.go:14-19`
```go
type RegisterRequest struct {
    TenantID string `json:"tenant_id" binding:"required"`
}
```
Attacker registers into any tenant by supplying its UUID.
**Fix:** Remove `tenant_id` from registration. Require admin invitation or fixed default tenant.

**C5. OIDC ID token signature not verified**
`api/oidc.go:322-355`
Token parsed without JWKS validation. Attacker can inject arbitrary claims.
**Fix:** Verify ID token signature against provider's JWKS endpoint.

### HIGH (11)

| # | Finding | Location |
|---|---------|----------|
| H1 | Sub-resource queries (steps, approvals) lack tenant_id | `handlers.go:253-264` |
| H2 | investigation_steps queried by task_id only | `handlers.go:683,1047` |
| H3 | SSE polling queries lack tenant_id | `sse.go:88,96` |
| H4 | Admin can view ANY tenant (not just own) | `tenants.go:66-109` |
| H5 | Admin can modify ANY tenant | `tenants.go:154-197` |
| H6 | Model registry has NO tenant isolation | `models.go:17-282` (all endpoints) |
| H7 | A/B tests have NO tenant isolation | `models.go:165-282` |
| H8 | Data retention policies global (no tenant) | `security.go:164-227` |
| H9 | Skills endpoint global (no tenant filter) | `handlers.go:881-927` |
| H10 | Webhook HMAC optional — missing secret = unauthenticated | `siem.go:53-62` |
| H11 | JSON injection in audit logs via fmt.Sprintf | `handlers.go:861`, `shadow.go:249`, `tokenquota.go:215` |

### MEDIUM (4)

| # | Finding | Location |
|---|---------|----------|
| M1 | OIDC cookies set with Secure=false | `oidc.go:140-141` |
| M2 | CORS hardcoded to localhost:3000 | `main.go:25` |
| M3 | Webhook source_id acts as secret (no tenant check) | `siem.go:33` |
| M4 | fmt.Sprintf for SSE data with unescaped output | `sse.go:110` |

### PASS

- All SQL queries use parameterized placeholders ($1, $2) — no injection
- Password hashing: bcrypt (cost=10)
- Account lockout: 5 attempts, 30min
- Auth rate limiting: 10/15min per IP
- Per-tenant rate limiting via Redis sliding windows
- Security headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy
- API key hashing: SHA-256 (raw shown once)
- PKCE for OIDC flows

---

## AUDIT 2: TENANT ISOLATION DEEP DIVE

### CRITICAL (7)

**T1. Tenant management endpoints allow cross-tenant access**
`tenants.go` — `listTenantsHandler` returns ALL tenants. `getTenantHandler` and `updateTenantHandler` accept URL `:id` parameter, not JWT tenant_id. Any admin of Tenant A can view/modify/disable Tenant B.

**T2. Registration self-assigns to any tenant** (same as C4)

**T3. Model registry and A/B tests have zero tenant isolation**
`models.go` — All queries are global. Any admin sees/modifies all models and tests across all tenants.

**T4. Data retention policies are global** (same as H8)

**T5. Investigation cache has no tenant_id in cache key**
`worker/investigation_cache.py:33-34`
```python
REDIS_CACHE_PREFIX = "zovark:inv_cache:"
```
Cache key is computed from IOC indicators only. Tenant A's cached results served to Tenant B for same indicators.

**T6. Semantic dedup has no tenant filter**
`worker/investigation_cache.py:179-242`
Vector similarity search matches investigations from ANY tenant.

**T7. Stampede coalescing has no tenant scoping**
`worker/stampede.py:81-82`
Coalescing keys lack tenant_id. Cross-tenant result sharing possible.

### HIGH (5)

| # | Finding | Location |
|---|---------|----------|
| T8 | Feedback IDOR — can submit for other tenant's investigation | `feedback.go:20-62` |
| T9 | Shadow record_human_decision has no tenant check | `worker/shadow.py:189-256` |
| T10 | Sub-resource queries (steps, approvals) lack tenant_id | `handlers.go:253-264` |
| T11 | SSE polling queries lack tenant_id | `sse.go:88-99` |
| T12 | fetch_task fetches by ID alone (no tenant enforcement) | `worker/activities.py:42-55` |

### MEDIUM (4)

| # | Finding | Location |
|---|---------|----------|
| T13 | Expired JWT bypass | `middleware.go:57-62` |
| T14 | OIDC role mapping trusts external claims | `oidc.go:233-245` |
| T15 | Skills listing is global | `handlers.go:881` |
| T16 | fetch_task in worker has no tenant enforcement | `activities.py:42-55` |

---

## AUDIT 3: PROMPT INJECTION

### CRITICAL (4)

**P1. Injection detector logs but does NOT block**
`worker/workflows.py:176-204`
`scan_for_injection()` fires, logs the event, but the workflow continues. Malicious data still flows into LLM prompts unchanged. The `injection_confidence` variable only tags entity graph edges — it never gates execution.

**P2. SIEM alert data injected directly into prompts without sanitization**
`worker/activities.py:129-138`
```python
augmented_prompt = (
    f"SIEM ALERT DATA:\n{siem_context}\n\n"
    f"Task: {prompt}\n\n"
)
```
Raw `siem_event` dict (all attacker-controlled fields from webhook) JSON-serialized directly into LLM prompt.

**P3. Prompt sanitizer only applied to `log_data`, not SIEM events**
`worker/workflows.py:206-220`
`wrap_untrusted_data()` only wraps `log_data` (file upload path). For SIEM-triggered investigations (the most common path), raw alert JSON goes into prompts with zero sanitization.

**P4. `autoInvestigateAlert` constructs prompt from raw SIEM fields**
`api/siem.go:218-221`
```go
prompt := fmt.Sprintf(
    "Investigate SIEM alert: %s. Source: %s, Dest: %s. Rule: %s. Severity: %s.",
    alertName, sourceIP, destIP, ruleName, severity,
)
```
All five fields come directly from external webhook payload with zero validation.

### HIGH (5)

| # | Finding | Location |
|---|---------|----------|
| P5 | Playbook system_prompt_override loaded from DB, injected raw | `activities.py:118-120` |
| P6 | Shadow mode generate_recommendation receives raw data | `shadow.py:63` |
| P7 | Entity extraction prompt includes raw investigation output | `prompts/entity_extraction.py:52-56` |
| P8 | Investigation prompt template receives raw alert data | `prompts/investigation_prompt.py:41-46` |
| P9 | fill_skill_parameters injects raw SIEM context | `activities.py:775-777` |
| P10 | LLM output drives risk_score and severity with no independent validation | `workflows.py:770-845` |

### DATA FLOW GAP

```
SIEM Webhook (untrusted) → api/siem.go (NO sanitization) → DB
→ worker/workflows.py → scan_for_injection (DETECT ONLY, no block)
→ wrap_untrusted_data (ONLY for log_data, NOT siem_event)
→ activities.py:generate_code (raw f-string interpolation)
→ LLM (injection possible)
```

**Sanitization coverage:** 3 of ~15 LLM call sites have wrapping. 12 receive raw data.

---

## AUDIT 4: SANDBOX ESCAPE

### CRITICAL (1)

**S1. Dry-run validator executes on worker host WITHOUT sandbox**
`worker/validation/dry_run.py:114-118`
```python
proc = await asyncio.create_subprocess_exec('python', temp_path, ...)
```
Code runs directly on the worker host with full access to: filesystem, network, environment variables (DB passwords, API keys), Docker socket. Only protection: 5s timeout + `resource.setrlimit` for memory.

### HIGH (3)

**S2. AST prefilter missing critical modules**
`sandbox/ast_prefilter.py:4-7`
**NOT blocked:** `os`, `subprocess`, `socket`, `requests`, `urllib`, `http`, `shutil`, `signal`, `sys`
**NOT blocked functions:** `compile`, `open`, `getattr`, `globals`, `type`
**NOT blocked dunders:** `__class__`, `__bases__`, `__subclasses__`, `__globals__`, `__dict__`, `__builtins__`

**S3. Deobfuscation template injection**
`worker/skills/deobfuscation.py:81-84`
User-controlled `encoded_payload` interpolated via f-string with inadequate escaping. Triple-quote breakout bypasses AST prefilter.

**S4. AST prefilter does not block dunder attribute traversal**
Python MRO traversal attack passes: `().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['system']('id')`

### SANDBOX ESCAPE VECTOR SCORECARD

| Vector | AST | Seccomp | Docker | Overall |
|--------|-----|---------|--------|---------|
| `__import__('os').system('id')` | BLOCKED (literal) | N/A | N/A | PASS (bypassable via getattr) |
| Subclass traversal | FAIL | Allows execve | Contained | **FAIL** |
| `open('/etc/passwd')` | FAIL | Allows open | Read-only (image files readable) | **FAIL** |
| Network socket | FAIL | Allows socket | BLOCKED (--network=none) | PASS |
| `exec(compile(...))` | BLOCKED (literal) | N/A | N/A | PASS (bypassable) |
| Fork bomb | FAIL | Allows fork | MITIGATED (pids=64) | PASS |
| Memory exhaustion | N/A | N/A | BLOCKED (512MB) | PASS |
| `/proc/self/environ` | FAIL | Allows open | Low risk (no secrets in container) | PASS |

### Docker Isolation (GOOD)

```
--network=none, --read-only, --cap-drop=ALL, --security-opt=no-new-privileges
--memory=512m, --cpus=0.5, --pids-limit=64, --tmpfs /tmp:64m,noexec,nosuid
seccomp profile applied, timeout=60s
```
Missing: `--user` flag (runs as root inside container).

---

## AUDIT 5: DATA PROTECTION

### CRITICAL (4)

**D1. Zero encryption at rest**
No `pgcrypto`, no column-level encryption. All sensitive data in plaintext:
- Investigation summaries, timelines, evidence
- SIEM raw alert data (IPs, hostnames, user identities)
- Entity values (emails, IPs, domains)
- **TOTP secrets** stored as `VARCHAR(64)` plaintext

**D2. PII masking is dead code — never called from workflows**
`mask_for_llm` and `unmask_response` activities are registered but never invoked from any workflow. All LLM calls send raw PII to external providers.

**D3. TLS disabled by default**
Caddy TLS is behind `profile: tls` — opt-in. All internal comms plaintext. `sslmode=disable` for Postgres.

**D4. Real API key committed to .env**
OpenRouter API key `sk-or-v1-...` on disk (gitignored, but present).

### HIGH (3)

| # | Finding | Detail |
|---|---------|--------|
| D5 | Redis has no authentication or TLS | Open on Docker network |
| D6 | NATS has no authentication or TLS | Open on port 4222 |
| D7 | Backup scripts produce unencrypted dumps | `scripts/backup-db.sh` — plain gzip |

### MEDIUM (2)

| # | Finding | Detail |
|---|---------|--------|
| D8 | Data retention policies defined but never enforced | No purge job exists |
| D9 | No GDPR erasure endpoint | No `DELETE /tenants/:id/data` |

### SCORECARD

| Category | Score | Rating |
|----------|-------|--------|
| Encryption at Rest | 0/10 | RED |
| Encryption in Transit | 2/10 | RED |
| Secrets Management | 5/10 | YELLOW |
| PII Handling | 3/10 | RED (built but not wired) |
| Key Management | 1/10 | RED |
| Data Retention | 3/10 | YELLOW |

---

## AUDIT 6: API SECURITY

### HIGH (3)

**A1. Rate limiting fails open on Redis failure**
`ratelimit.go:88` — returns `true` (allow) when Redis is down. All rate limiting bypassed.
**Fix:** Fail-closed or local fallback limiter.

**A2. No request body size limit**
`siem.go:46` — `io.ReadAll(c.Request.Body)` with no limit. Multi-GB payload = OOM DoS.
**Fix:** Add `http.MaxBytesReader` globally. `io.LimitReader` on webhook handler.

**A3. Database errors leaked to clients**
35+ handlers pass raw `err.Error()` to JSON responses. Exposes table names, column names, constraints.
**Fix:** Never pass `err.Error()` to clients. Use generic messages.

### MEDIUM (2)

| # | Finding | Detail |
|---|---------|--------|
| A4 | No CSP or HSTS headers | `security.go:18-28` missing |
| A5 | Admin OpenAPI endpoints documented publicly | `docs/openapi.yaml` |

### PASS

- CORS correctly restricted to `localhost:3000` (not wildcard)
- Rate limit headers returned (X-RateLimit-*)
- Sort column whitelisting in query builders
- Pagination bounds checking (limit capped at 100)
- HMAC-SHA256 on webhooks (when configured)

---

## TOP 10 PRIORITY FIXES

### P0 — Fix Before ANY External Access

| # | Fix | Files | Effort | Status |
|---|-----|-------|--------|--------|
| 1 | **Block injection detector** — reject/quarantine when `injection_detected` | `worker/workflows.py:176-212` | 2hr | **FIXED v0.10.2** |
| 2 | **Wire PII masking into workflows** — call `mask_for_llm` before LLM calls | `worker/workflows.py` | 4hr | **FIXED v0.10.2** |
| 3 | **Remove expired JWT bypass** | `api/middleware.go:57-62` | 30min | **FIXED v0.10.1** |
| 4 | **Validate tenant_id in registration** — verify tenant exists + active | `api/auth.go:36-48` | 2hr | **FIXED v0.10.2** |
| 5 | **Fail startup without JWT_SECRET** — no hardcoded default | `api/main.go:40-43` | 30min | **FIXED v0.10.1** |
| 6 | **Add request body size limit** — prevent OOM DoS | `api/siem.go:46` + `api/security.go` | 1hr | **FIXED v0.10.2** |
| 7 | **Fix investigation cache tenant isolation** — add tenant_id to cache keys | `worker/investigation_cache.py`, `worker/stampede.py` | 3hr | **FIXED v0.10.2** |
| 8 | **Scope tenant CRUD to own tenant** | `api/tenants.go` | 3hr | **FIXED v0.10.2** |
| 9 | **Move dry-run validation into Docker sandbox** | `worker/validation/dry_run.py:84-130` | 4hr | **FIXED v0.10.2** |
| 10 | **Sanitize SIEM fields before prompt construction** | `api/siem.go:200-221`, `worker/activities.py:130-138` | 2hr | **FIXED v0.10.2** |

### P1 — Fix Before Pilot Onboarding

| # | Fix | Effort | Status |
|---|-----|--------|--------|
| 11 | Add OIDC JWKS signature verification | 4hr | **FIXED v0.10.1** |
| 12 | Add tenant_id to model registry/A/B tests/retention policies | 3hr | **FIXED v0.11.0** |
| 13 | Expand AST prefilter forbidden list (os, subprocess, socket, dunders) | 2hr | **FIXED v0.11.0** |
| 14 | Apply `wrap_untrusted_data()` to all 12 unsanitized LLM call sites | 6hr | **FIXED v0.11.0** |
| 15 | Stop leaking err.Error() to clients (35+ handlers) | 4hr | **FIXED v0.11.0** |
| 16 | Rate limit fail-closed on Redis failure | 2hr | **FIXED v0.11.0** |
| 17 | Enable TLS by default (Caddy, sslmode=require) | 3hr | **FIXED v0.11.0** |
| 18 | Add independent validation of LLM-derived risk scores | 4hr | **FIXED v0.11.0** |
| 19 | Fix deobfuscation template injection | 1hr | **FIXED v0.11.0** |
| 20 | Use json.Marshal for all audit log JSON construction | 2hr | **FIXED v0.11.0** |

### P2 — Fix Before GA

| # | Fix | Effort | Status |
|---|-----|--------|--------|
| 21 | Encrypt TOTP secrets at rest (pgcrypto or app-level AES) | 4hr | **FIXED v0.11.0** |
| 22 | Column-level encryption for sensitive investigation data | 8hr | **FIXED v0.11.0** |
| 23 | Redis authentication + TLS | 2hr | **FIXED v0.11.0** |
| 24 | NATS authentication + TLS | 2hr | **FIXED v0.11.0** |
| 25 | Implement data retention enforcement job | 4hr | **FIXED v0.11.0** |
| 26 | Add CSP and HSTS headers | 1hr | **FIXED v0.11.0** |
| 27 | PostgreSQL row-level security (RLS) | 8hr | **FIXED v0.11.0** |
| 28 | GDPR erasure endpoint | 4hr | **FIXED v0.11.0** |
| 29 | Encrypt database backups | 1hr | **FIXED v0.11.0** |
| 30 | Add --user flag to sandbox Docker containers | 30min | **FIXED v0.11.0** |

---

## APPENDIX: FILES REQUIRING IMMEDIATE ATTENTION

| File | Critical Issues |
|------|----------------|
| `api/middleware.go:57` | Expired JWT bypass |
| `api/main.go:40,43` | Hardcoded DB password + JWT secret |
| `api/auth.go:14` | Open registration with attacker-chosen tenant |
| `api/oidc.go:322` | No ID token signature verification |
| `api/tenants.go:66,154` | Cross-tenant admin access |
| `api/models.go:17-282` | Global model operations, no tenant isolation |
| `api/siem.go:46,218` | No body size limit + raw fields in prompt |
| `api/handlers.go:253,683,861` | Sub-resource BOLA + JSON injection |
| `worker/workflows.py:176` | Injection detector doesn't block |
| `worker/activities.py:129` | Raw SIEM data in LLM prompts |
| `worker/investigation_cache.py:33` | Cache keys lack tenant_id |
| `worker/validation/dry_run.py:114` | Code execution on worker host |
| `worker/pii_detector.py` | Built but never called (dead code) |
| `sandbox/ast_prefilter.py:4` | Missing os, subprocess, socket from blacklist |

---

**Report generated:** 2026-03-13
**Total findings:** 21 Critical, 30 High, 17 Medium, 2 Low
**Estimated remediation:** ~90 engineer-hours for P0+P1
**Recommendation:** Address all P0 items before any shadow mode pilot deployment
