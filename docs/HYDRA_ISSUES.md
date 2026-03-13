# HYDRA MVP — GitHub Issues Tracker

> 50 issues across 8 milestones. Each issue is self-contained, actionable, and ready for implementation.
> Import to GitHub via `gh issue create` or manually.

---

## Milestones

| Milestone | Focus | Issues |
|-----------|-------|--------|
| **M1: Production Foundation** | Security, TLS, secrets, auth hardening | #1–#7 |
| **M2: API & SDK** | OpenAPI spec, rate limiting, SDK, bulk ops | #8–#14 |
| **M3: Dashboard Evolution** | Admin panel, approval queue, cost tracking | #15–#23 |
| **M4: Integrations** | Slack, Jira, SIEM connectors, TI feeds | #24–#31 |
| **M5: Intelligence & RAG** | Vector indexes, semantic search, fine-tuning | #32–#38 |
| **M6: Testing & Quality** | E2E tests, CI hardening, accuracy framework | #39–#44 |
| **M7: Deployment & Scale** | Container registry, Helm, backup, multi-region | #45–#50 |
| **M8: Workflow Automation** | Auto-triggers, scheduling, playbook wiring | #51–#55 |

---

## M1: Production Foundation

### Issue #1: SSO/OAuth2 — OIDC provider integration

**Priority:** Critical | **Milestone:** M1: Production Foundation | **Labels:** security, backend, priority:critical

#### Description

HYDRA currently supports email/password authentication only (bcrypt + JWT). Enterprise deployments require SSO via existing identity providers (Okta, Azure AD/Entra ID, Google Workspace). Without this, no enterprise customer will adopt HYDRA in production.

#### Acceptance Criteria

- [ ] Add OIDC discovery endpoint support (`/.well-known/openid-configuration`)
- [ ] Implement authorization code flow with PKCE
- [ ] Support Google, Microsoft (Entra ID), and Okta as providers
- [ ] Environment variables: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`
- [ ] Map OIDC claims to HYDRA roles: `admin`, `analyst`, `viewer` via configurable claim key
- [ ] Auto-provision users on first login (JIT provisioning) with tenant assignment
- [ ] Fallback to email/password when OIDC is not configured
- [ ] Update `/api/v1/auth/login` to return redirect URL for OIDC flow
- [ ] Add `/api/v1/auth/callback` endpoint to handle OIDC response
- [ ] Store `external_auth_id` in users table (column already exists)
- [ ] Update dashboard login page with "Sign in with SSO" button

#### Technical Notes

- Use Go `coreos/go-oidc` library for token verification
- JWT issued by HYDRA after OIDC validation (don't pass through provider JWT)
- Session state stored in Redis during auth flow (5-minute TTL)
- `users.external_auth_id` already exists in schema — use it for OIDC subject mapping
- Keep existing bcrypt login path for air-gap deployments

---

### Issue #2: TLS termination — HTTPS enforcement for all services

**Priority:** Critical | **Milestone:** M1: Production Foundation | **Labels:** security, deployment, priority:critical

#### Description

All HYDRA services communicate over plaintext HTTP on localhost. Production deployments must encrypt traffic between browser ↔ API, API ↔ LiteLLM, and API ↔ Temporal. Credentials (JWT, API keys, webhook secrets) are transmitted unencrypted.

#### Acceptance Criteria

- [ ] Add Caddy or Traefik reverse proxy service to `docker-compose.yml`
- [ ] Auto-generate self-signed certs for development (mkcert)
- [ ] Let's Encrypt ACME support for production domains
- [ ] API (port 8090) accessible only via HTTPS (443)
- [ ] Dashboard (port 3000) served behind reverse proxy
- [ ] Internal services (Temporal, Postgres, Redis, LiteLLM) remain HTTP on `hydra-internal` network
- [ ] `HYDRA_TLS_ENABLED=true` environment variable to toggle
- [ ] HSTS header on all API responses when TLS enabled
- [ ] Update dashboard API base URL to use `https://` when configured
- [ ] Document certificate setup in DEPLOYMENT_GUIDE.md

#### Technical Notes

- Caddy is simplest (auto-TLS, zero-config); Traefik is more flexible (Docker labels)
- Internal network traffic stays HTTP — TLS only at ingress
- K8s overlay should use cert-manager + Ingress instead of Caddy

---

### Issue #3: Secrets management — Vault integration for credentials

**Priority:** High | **Milestone:** M1: Production Foundation | **Labels:** security, backend, priority:high

#### Description

HYDRA stores all secrets in `.env` files and environment variables: `POSTGRES_PASSWORD`, `LITELLM_MASTER_KEY`, `MINIO_ROOT_PASSWORD`, webhook secrets, JWT signing key. These are visible in `docker inspect`, process environment, and logs. Production requires a proper secrets manager.

#### Acceptance Criteria

- [ ] Abstract secret loading behind `secrets.Get(key)` function in Go API
- [ ] Abstract secret loading behind `get_secret(key)` function in Python worker
- [ ] Support 3 backends: environment variables (default), HashiCorp Vault, AWS Secrets Manager
- [ ] `HYDRA_SECRETS_BACKEND=env|vault|aws` environment variable
- [ ] Vault backend: AppRole auth, KV v2 engine, `hydra/` mount path
- [ ] AWS backend: IAM role-based, no access keys in config
- [ ] Rotate database password without downtime (PgBouncer handles reconnection)
- [ ] JWT signing key rotation: support multiple active keys (JWK set)
- [ ] Remove all hardcoded secrets from `docker-compose.yml` (use `_FILE` suffix pattern)
- [ ] Add `scripts/rotate-secrets.sh` helper

#### Technical Notes

- Start with `_FILE` suffix pattern (Docker secrets) for simplest production use
- Vault dev server in docker-compose for testing
- PgBouncer already handles connection pooling — password rotation is seamless

---

### Issue #4: Two-factor authentication (TOTP)

**Priority:** High | **Milestone:** M1: Production Foundation | **Labels:** security, backend, frontend, priority:high

#### Description

Admin and analyst accounts need 2FA to prevent credential theft. HYDRA currently relies on password-only authentication. Add TOTP (Time-based One-Time Password) support compatible with Google Authenticator, Authy, and 1Password.

#### Acceptance Criteria

- [ ] Add `totp_secret` (encrypted) and `totp_enabled` columns to `users` table
- [ ] `POST /api/v1/auth/2fa/setup` — Generate TOTP secret, return QR code URI
- [ ] `POST /api/v1/auth/2fa/verify` — Verify TOTP code and enable 2FA
- [ ] `POST /api/v1/auth/2fa/disable` — Disable 2FA (requires current TOTP code)
- [ ] Login flow: if `totp_enabled=true`, require TOTP code after password verification
- [ ] Generate 10 backup recovery codes on setup (stored hashed)
- [ ] Rate-limit TOTP verification: 5 attempts per 5 minutes
- [ ] Dashboard: 2FA setup page in user settings with QR code display
- [ ] Admins can enforce 2FA for all users in tenant settings

#### Technical Notes

- Use `pquerna/otp` library in Go for TOTP generation/verification
- 30-second window, 6-digit codes, SHA1 algorithm (Google Authenticator compatible)
- Encrypt `totp_secret` at rest using AES-256-GCM with key from secrets manager

---

### Issue #5: API key authentication for machine-to-machine access

**Priority:** High | **Milestone:** M1: Production Foundation | **Labels:** security, backend, priority:high

#### Description

External systems (SIEM, ticketing, custom scripts) need to call HYDRA's API without user JWT tokens. Add API key support with per-key permissions, rate limits, and audit logging. Currently only JWT auth exists.

#### Acceptance Criteria

- [ ] New `api_keys` table: id, tenant_id, name, key_hash (SHA-256), prefix (first 8 chars), permissions (JSONB), rate_limit, last_used_at, expires_at, created_by, created_at
- [ ] `POST /api/v1/api-keys` — Create key (returns full key once, stores hash only)
- [ ] `GET /api/v1/api-keys` — List keys (prefix only, never full key)
- [ ] `DELETE /api/v1/api-keys/:id` — Revoke key
- [ ] Accept `X-API-Key` header on all endpoints (alternative to Bearer JWT)
- [ ] Per-key permissions: `tasks:read`, `tasks:write`, `alerts:write`, `admin:*`
- [ ] Per-key rate limit override (default: 300 req/min)
- [ ] Audit log entries include `api_key_id` when used
- [ ] Key format: `hydra_sk_` prefix + 32 random bytes (base62 encoded)
- [ ] Keys scoped to single tenant (multi-tenant isolation preserved)

#### Technical Notes

- Store SHA-256 hash of key, never plaintext
- Prefix (`hydra_sk_abc12345`) stored separately for identification in lists
- Auth middleware: check `X-API-Key` first, then `Authorization: Bearer` JWT
- Migration: `migrations/020_api_keys.sql`

---

### Issue #6: Database backup automation with S3/MinIO snapshots

**Priority:** High | **Milestone:** M1: Production Foundation | **Labels:** deployment, backend, priority:high

#### Description

PostgreSQL data is stored on Docker volumes with no backup strategy. A disk failure loses all investigations, entities, and configuration. Implement automated pg_dump to MinIO (already running) with retention policies.

#### Acceptance Criteria

- [ ] New service `hydra-backup` in docker-compose (lightweight Alpine + pg_dump + mc)
- [ ] Schedule: daily full backup at 02:00 UTC, hourly WAL archiving
- [ ] Store backups in MinIO bucket `hydra-backups/` with date-prefixed paths
- [ ] Retention: 7 daily, 4 weekly, 3 monthly snapshots (oldest auto-deleted)
- [ ] `scripts/backup.sh` — Manual backup trigger
- [ ] `scripts/restore.sh` — Point-in-time recovery from MinIO snapshot
- [ ] Backup encryption: AES-256 with key from secrets config
- [ ] Backup verification: restore to temp DB, verify table counts, delete
- [ ] Health check: alert if last successful backup > 25 hours ago
- [ ] Prometheus metric: `hydra_backup_last_success_timestamp`

#### Technical Notes

- Use `pg_dump --format=custom` for compression and selective restore
- MinIO already running on port 9000/9001 — reuse existing instance
- WAL archiving requires `archive_mode=on` in postgresql.conf (add to postgres service command)

---

### Issue #7: Audit log export and SIEM forwarding

**Priority:** Medium | **Milestone:** M1: Production Foundation | **Labels:** security, backend, priority:medium

#### Description

Audit events are stored in PostgreSQL `audit_events` table only. Compliance requires forwarding audit logs to external SIEM (Splunk, Elastic) and archival to object storage. Currently no export mechanism exists.

#### Acceptance Criteria

- [ ] `GET /api/v1/audit/export` — Download audit logs as JSONL (date range filter, max 10k records)
- [ ] Syslog forwarding: configure `HYDRA_SYSLOG_TARGET=tcp://splunk:514` to stream events
- [ ] CEF format support (Common Event Format) for SIEM compatibility
- [ ] S3/MinIO archival: daily export of audit_events older than 30 days
- [ ] Retention policy: delete archived events from DB after S3 confirmation
- [ ] Include all event types: login, task creation, approval, self-healing, injection detected
- [ ] Tamper detection: HMAC chain on exported logs (each entry signs previous hash)
- [ ] Dashboard: audit log viewer with search, filter by event_type, date range, actor

#### Technical Notes

- Use Go `log/syslog` package for syslog forwarding
- CEF format: `CEF:0|HYDRA|SOC-Agent|1.0|event_type|description|severity|extension`
- Batch export to avoid memory issues (stream rows, don't load all into memory)

---

## M2: API & SDK

### Issue #8: OpenAPI 3.1 specification with Swagger UI

**Priority:** High | **Milestone:** M2: API & SDK | **Labels:** backend, documentation, priority:high

#### Description

HYDRA has 44+ API endpoints documented only in markdown files. No interactive API explorer exists. Generate an OpenAPI 3.1 spec from Go handlers and serve Swagger UI for developers. This unblocks SDK auto-generation (#10) and client validation.

#### Acceptance Criteria

- [ ] Generate `openapi.yaml` from Go handler annotations (use `swaggo/swag` or hand-write)
- [ ] Serve Swagger UI at `/api/docs` (embed swagger-ui-dist)
- [ ] Document all 44+ endpoints: paths, methods, parameters, request/response bodies, auth requirements
- [ ] Include schema definitions for all request/response types
- [ ] Auth schemes: Bearer JWT (`hydra_jwt`) and API Key (`hydra_api_key`)
- [ ] Example values for all fields (realistic SOC data)
- [ ] Error response schemas: `{error: {code, message, details}}`
- [ ] Validate spec with `swagger-cli validate openapi.yaml` in CI
- [ ] Version header: `X-API-Version: 1.0.0`

#### Technical Notes

- `swaggo/swag` generates from Go comments (`// @Summary`, `// @Param`, etc.)
- Alternatively, hand-write YAML and validate — more control, less coupling
- Swagger UI served as static files behind the Go server (no extra service)

---

### Issue #9: Consistent API response envelope and error format

**Priority:** High | **Milestone:** M2: API & SDK | **Labels:** backend, priority:high

#### Description

API responses use inconsistent formats: some return raw data, others wrap in objects. Error responses vary between handlers. Standardize all responses into a predictable envelope that SDKs and frontends can reliably parse.

#### Acceptance Criteria

- [ ] Success responses: `{"data": {...}, "meta": {"request_id": "...", "timestamp": "..."}}`
- [ ] List responses: `{"data": [...], "meta": {"total": N, "page": N, "per_page": N, "request_id": "..."}}`
- [ ] Error responses: `{"error": {"code": "VALIDATION_FAILED", "message": "...", "details": [...]}}`
- [ ] Add `X-Request-Id` header to all responses (UUID, generated per request)
- [ ] Propagate request ID through Temporal workflow execution for tracing
- [ ] Add gzip compression middleware (Accept-Encoding: gzip)
- [ ] HTTP status codes: 200 (success), 201 (created), 400 (validation), 401 (auth), 403 (forbidden), 404 (not found), 429 (rate limit), 500 (internal)
- [ ] Error codes enum: `AUTH_FAILED`, `VALIDATION_FAILED`, `NOT_FOUND`, `RATE_LIMITED`, `INTERNAL_ERROR`, `TENANT_MISMATCH`
- [ ] Update all 44+ handlers to use envelope helpers: `respondOK(w, data)`, `respondError(w, code, message)`
- [ ] Update dashboard to parse new envelope format

#### Technical Notes

- Create `api/response.go` with helper functions
- Backward-compatible migration: add `X-Hydra-Envelope: true` header, dashboard checks for it
- Request ID generated in middleware, stored in `context.Context`

---

### Issue #10: Python SDK — typed client library for HYDRA API

**Priority:** High | **Milestone:** M2: API & SDK | **Labels:** sdk, priority:high

#### Description

Every HYDRA integration must hand-craft HTTP calls to 44+ endpoints. A typed Python SDK reduces integration time from hours to minutes. Python is the dominant SOC scripting language.

#### Acceptance Criteria

- [ ] Package: `hydra-sdk` (publishable to PyPI)
- [ ] Typed client: `HydraClient(base_url, api_key=None, jwt_token=None)`
- [ ] Methods for all endpoint groups: `client.tasks.list()`, `client.tasks.create(...)`, `client.alerts.investigate(...)`, etc.
- [ ] Response models: dataclasses for Task, Investigation, Alert, Entity, Playbook
- [ ] Async support: `AsyncHydraClient` using `httpx.AsyncClient`
- [ ] Pagination helpers: `client.tasks.list_all()` auto-paginates
- [ ] Error handling: `HydraAPIError`, `HydraAuthError`, `HydraRateLimitError`
- [ ] Retry logic: exponential backoff on 429/503 (configurable)
- [ ] Auth: API key via `X-API-Key`, JWT via `Authorization: Bearer`
- [ ] Minimal dependencies: `httpx`, `dataclasses` only
- [ ] `README.md` with quickstart, examples for common SOC workflows

#### Technical Notes

- Generate from OpenAPI spec (#8) using `openapi-python-client` or hand-write for quality
- Directory: `sdk/python/` in monorepo
- Publish to PyPI as `hydra-soc-sdk` (avoid name conflicts)

---

### Issue #11: Per-tenant API rate limiting with Redis

**Priority:** High | **Milestone:** M2: API & SDK | **Labels:** backend, priority:high

#### Description

HYDRA rate-limits only auth endpoints (10 req/15min per IP). Task submission, alert ingestion, and API queries have no limits. A single tenant can exhaust worker capacity or DOS the database. Implement tiered, per-tenant rate limiting using Redis.

#### Acceptance Criteria

- [ ] Rate limit middleware in Go API using Redis sliding window counter
- [ ] Tiers: `free` (30 req/min), `professional` (120 req/min), `enterprise` (600 req/min)
- [ ] Separate limits for: general API, task creation (stricter), webhook ingestion, bulk operations
- [ ] Response headers on all requests: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- [ ] 429 response with `Retry-After` header when exceeded
- [ ] Per-tenant override in `tenants.settings` JSONB: `{"rate_limit": {"api": 200, "tasks": 50}}`
- [ ] Admin endpoints exempt from rate limiting
- [ ] Burst allowance: 2x limit for 10-second window
- [ ] Prometheus metrics: `hydra_api_rate_limited_total{tenant, endpoint}`
- [ ] Dashboard indicator when approaching limit

#### Technical Notes

- Use Redis `MULTI`/`EXEC` for atomic sliding window (key: `rl:{tenant}:{endpoint}:{minute}`)
- Redis already running in stack — no new service needed
- Go middleware: extract tenant from JWT claims, check Redis, return headers

---

### Issue #12: Bulk task creation endpoint

**Priority:** Medium | **Milestone:** M2: API & SDK | **Labels:** backend, priority:medium

#### Description

SOC teams often need to investigate batches of alerts (morning triage, IR response). Currently tasks are created one-at-a-time via `POST /api/v1/tasks`. Add bulk creation for efficiency.

#### Acceptance Criteria

- [ ] `POST /api/v1/tasks/bulk` — Accept array of up to 100 task definitions
- [ ] Validate all tasks before creating any (atomic batch)
- [ ] Deduplication: skip alerts matching existing fingerprints (return `skipped` status)
- [ ] Response: `{"data": {"created": [...ids], "skipped": [...reasons], "failed": [...errors]}}`
- [ ] Queue all created tasks to Temporal in parallel (fan-out)
- [ ] Rate limit: bulk endpoint has separate, stricter limit (10 req/min)
- [ ] Priority ordering: high-severity tasks queued first
- [ ] Webhook notification: single `bulk_tasks_created` event (not per-task)

#### Technical Notes

- Use database transaction for atomic insert (all or nothing)
- Temporal `workflow.start()` calls can be parallelized with goroutines
- File upload variant: accept CSV/JSONL file with task definitions

---

### Issue #13: Investigation report export (PDF + JSON)

**Priority:** Medium | **Milestone:** M2: API & SDK | **Labels:** backend, priority:medium

#### Description

Investigation results are viewable only in the dashboard. Analysts need to export reports for ticketing systems, management briefings, and compliance. The worker has `generate_incident_report` (markdown) but no PDF rendering or API endpoint.

#### Acceptance Criteria

- [ ] `GET /api/v1/tasks/:id/report` — Return investigation report (Accept header: `application/json`, `application/pdf`, `text/markdown`)
- [ ] JSON format: structured report with findings, entities, timeline, verdict, confidence
- [ ] Markdown format: human-readable report (already generated by worker activity)
- [ ] PDF format: styled PDF with HYDRA logo, table of contents, entity tables, code blocks
- [ ] Include: executive summary, investigation steps, code executed, findings, entities extracted, verdict, recommendations
- [ ] PDF styling: consistent branding, syntax-highlighted code blocks
- [ ] Caching: store generated report in MinIO, serve cached version on repeat requests
- [ ] Dashboard: "Download Report" button on task detail page (PDF + JSON options)

#### Technical Notes

- PDF generation: use `chromedp` (headless Chrome) or `wkhtmltopdf` in Go
- Alternatively: render markdown to HTML, then HTML to PDF
- Store in MinIO: `reports/{tenant_id}/{task_id}/report.pdf`

---

### Issue #14: Content negotiation — CSV and JSONL export for lists

**Priority:** Low | **Milestone:** M2: API & SDK | **Labels:** backend, priority:low

#### Description

All API list endpoints return JSON only. SOC teams need CSV export for Excel analysis and JSONL for log ingestion pipelines. Add content negotiation via `Accept` header.

#### Acceptance Criteria

- [ ] Support `Accept: text/csv` on list endpoints (tasks, alerts, entities, audit logs)
- [ ] Support `Accept: application/x-ndjson` for JSONL streaming
- [ ] CSV includes header row with column names
- [ ] JSONL streams one record per line (memory-efficient for large exports)
- [ ] `?format=csv` query parameter as alternative to Accept header
- [ ] Filename header: `Content-Disposition: attachment; filename="tasks-2026-03-11.csv"`
- [ ] Date range filter: `?from=2026-03-01&to=2026-03-11` for export scoping
- [ ] Max export: 50,000 records (paginated streaming for larger sets)

#### Technical Notes

- Use Go `encoding/csv` writer streaming directly to ResponseWriter
- JSONL: `json.NewEncoder(w).Encode(row)` per row (no buffering)
- Don't load all rows into memory — stream from database cursor

---

## M3: Dashboard Evolution

### Issue #15: Admin panel — tenant management UI

**Priority:** High | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:high

#### Description

Tenant CRUD exists via API but has no UI. Admins must use curl/Postman to manage tenants, view usage, configure settings. Add an admin panel accessible to users with `admin` role.

#### Acceptance Criteria

- [ ] Admin section at `/admin` route (guarded by role check)
- [ ] Sidebar navigation: Tenants, Users, Models, System Health
- [ ] Tenant list: table with name, slug, tier, user count, task count, status
- [ ] Tenant detail: settings editor (JSONB), usage stats, rate limit config
- [ ] Create tenant form: name, slug, tier selection, initial admin user
- [ ] User management: list users per tenant, change roles, lock/unlock accounts
- [ ] System stats: total tasks, active investigations, LLM token usage, error rate
- [ ] Activity feed: recent audit events across all tenants

#### Technical Notes

- Reuse existing API endpoints (`/api/v1/tenants`, `/api/v1/audit/export`)
- Admin routes check `role === 'admin'` from JWT claims
- Separate React Router nested route: `/admin/*`

---

### Issue #16: Approval queue UI — visual pending approvals

**Priority:** High | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:high

#### Description

High-risk investigation steps require approval (sandbox code execution with network access, destructive operations). Currently approvals are managed via API only. Analysts need a visual queue to review, approve, or reject pending actions.

#### Acceptance Criteria

- [ ] Approval queue page at `/approvals`
- [ ] Card-based layout: each pending approval shows investigation context, generated code, risk assessment
- [ ] Code viewer: syntax-highlighted Python code with dangerous operations highlighted in red
- [ ] Context panel: what triggered this investigation, what was found so far
- [ ] Actions: Approve (green), Reject (red) with required comment, Skip
- [ ] Real-time updates: new approvals appear without page refresh (polling or SSE)
- [ ] Notification badge: count of pending approvals in sidebar
- [ ] Approval history: list of past decisions with timestamps and reviewer
- [ ] Mobile-responsive: swipe to approve/reject on phone

#### Technical Notes

- Use existing `GET /api/v1/approvals/pending` and `POST /api/v1/approvals/:id/decide`
- Poll every 10 seconds for new approvals (SSE later)
- Syntax highlighting: use `react-syntax-highlighter` (already available via Prism)

---

### Issue #17: LLM cost tracking dashboard

**Priority:** High | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:high

#### Description

HYDRA logs all LLM calls to `llm_call_log` table with token counts and cost estimates. This data is not visible in the dashboard. Add a cost tracking panel for budget awareness and optimization.

#### Acceptance Criteria

- [ ] Cost overview page at `/costs`
- [ ] Summary cards: total cost (24h, 7d, 30d), avg cost per investigation, total tokens
- [ ] Cost breakdown by model tier: fast vs standard vs reasoning (bar chart)
- [ ] Cost breakdown by activity: which activities consume most tokens (pie chart)
- [ ] Daily cost trend: line chart over last 30 days
- [ ] Per-investigation cost: show token cost on task detail page
- [ ] Budget alerts: configurable threshold, banner when approaching limit
- [ ] Cost by tenant: admin view of per-tenant spending
- [ ] Export: CSV download of cost data

#### Technical Notes

- New API endpoint: `GET /api/v1/costs/summary?period=7d`
- Aggregate from `llm_call_log` table (already has `estimated_cost_usd`)
- Use Recharts or Chart.js for visualizations
- `investigation_costs` view already exists in DB — use it

---

### Issue #18: Entity graph visualization

**Priority:** Medium | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:medium

#### Description

HYDRA extracts entities (IPs, domains, hashes, users, processes) and builds relationship graphs in the database. This graph is invisible to analysts. Visualize entity connections to reveal attack patterns and lateral movement.

#### Acceptance Criteria

- [ ] Entity graph tab on investigation detail page
- [ ] Force-directed graph layout: entities as nodes, relationships as edges
- [ ] Node styling: color by entity type (IP=blue, domain=green, hash=orange, user=purple)
- [ ] Node size: proportional to connection count
- [ ] Edge labels: relationship type (communicates_with, resolved_to, logged_in_from, etc.)
- [ ] Click node: show entity details (verdict, confidence, first/last seen, related investigations)
- [ ] Hover edge: show evidence supporting the relationship
- [ ] Cross-investigation view: show entities shared across multiple investigations
- [ ] Zoom, pan, fullscreen support
- [ ] Export as PNG or SVG

#### Technical Notes

- Use D3.js force simulation or `react-force-graph-2d`
- New API endpoint: `GET /api/v1/tasks/:id/entities` (with edges)
- Limit to 200 nodes for performance (paginate or cluster beyond that)

---

### Issue #19: Real-time investigation updates via Server-Sent Events

**Priority:** Medium | **Milestone:** M3: Dashboard Evolution | **Labels:** backend, frontend, priority:medium

#### Description

Investigation progress is shown by polling the API every few seconds. This creates unnecessary load and delayed updates. Implement SSE (Server-Sent Events) for real-time push of investigation step completions, approvals, and verdicts.

#### Acceptance Criteria

- [ ] `GET /api/v1/events/stream` — SSE endpoint (text/event-stream)
- [ ] Event types: `investigation.step_started`, `investigation.step_completed`, `investigation.completed`, `approval.requested`, `approval.decided`, `alert.received`
- [ ] Filter by tenant (from JWT) — only receive own tenant's events
- [ ] Heartbeat: send `:keepalive` comment every 30 seconds
- [ ] Client reconnection: support `Last-Event-ID` header for resuming
- [ ] Dashboard: replace polling with SSE connection on task detail and task list pages
- [ ] Connection management: max 1 SSE connection per browser tab
- [ ] Fallback: if SSE fails, revert to polling (10-second interval)

#### Technical Notes

- Go: use `http.Flusher` interface, set `Content-Type: text/event-stream`
- Fan-out: use Redis pub/sub to distribute events from worker to API instances
- Worker publishes events to Redis channel `hydra:events:{tenant_id}` on step completion
- Dashboard: `new EventSource('/api/v1/events/stream')` with reconnect logic

---

### Issue #20: Investigation timeline view with MITRE ATT&CK mapping

**Priority:** Medium | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:medium

#### Description

Investigation steps are displayed as a flat list. Map each step's findings to MITRE ATT&CK techniques and display as an interactive timeline showing attack progression through the kill chain.

#### Acceptance Criteria

- [ ] Timeline component on task detail page (horizontal or vertical)
- [ ] Each step mapped to MITRE ATT&CK tactic/technique (from entity extraction)
- [ ] Kill chain phases: Reconnaissance → Initial Access → Execution → Persistence → ... → Impact
- [ ] Visual indicators: which phases were observed in this investigation
- [ ] Click technique: link to MITRE ATT&CK page + show evidence from investigation
- [ ] Coverage heat map: which kill chain phases HYDRA detects well vs gaps
- [ ] Overlay: show entities involved at each phase
- [ ] Export: STIX 2.1 bundle of investigation findings

#### Technical Notes

- MITRE mapping already exists in `mitre_techniques` table (691 techniques loaded)
- Entity extraction returns technique_ids — use these for mapping
- STIX export: use JSON schema from OASIS standard

---

### Issue #21: Dark mode / light mode toggle

**Priority:** Low | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:low

#### Description

Dashboard is currently dark-theme only. Some analysts prefer light mode, especially in bright SOC environments. Add a toggle with system preference detection.

#### Acceptance Criteria

- [ ] Toggle button in header (sun/moon icon)
- [ ] Respect `prefers-color-scheme` media query on first visit
- [ ] Persist preference in localStorage
- [ ] Tailwind dark mode classes already used — switch `class` strategy
- [ ] Smooth transition animation (150ms)
- [ ] All components readable in both modes (check contrast ratios)

---

### Issue #22: Playbook builder UI — visual workflow editor

**Priority:** Medium | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:medium

#### Description

Response playbooks are created via API with JSON definitions. Analysts need a visual drag-and-drop editor to build investigation and response playbooks without writing JSON.

#### Acceptance Criteria

- [ ] Playbook builder page at `/playbooks/new` and `/playbooks/:id/edit`
- [ ] Drag-and-drop canvas: add steps from palette (notify, ticket, quarantine, isolate, remediate, rollback)
- [ ] Step configuration: click step to set parameters (target, timeout, requires_approval)
- [ ] Conditional branching: if verdict = true_positive → quarantine, else → close
- [ ] Trigger configuration: which alert types/severities auto-trigger this playbook
- [ ] Preview mode: dry-run visualization showing what would happen
- [ ] Save: serialize to playbook JSON format, save via API
- [ ] Template library: pre-built playbooks for common scenarios (phishing, ransomware, C2)

#### Technical Notes

- Use `reactflow` library for node-based visual editor
- Playbook JSON schema already defined in `response/` module
- Existing playbooks (5 templates) should be loadable in editor

---

### Issue #23: SIEM alerts management UI with filtering

**Priority:** High | **Milestone:** M3: Dashboard Evolution | **Labels:** frontend, priority:high

#### Description

SIEM alerts page exists but shows minimal data with no filtering. Analysts need to triage alerts efficiently: filter by severity, source, status, date range, and keyword search.

#### Acceptance Criteria

- [ ] Enhanced alerts page at `/alerts`
- [ ] Filter bar: severity (critical/high/medium/low), status (new/investigating/resolved/false_positive), source (log source name), date range
- [ ] Search: full-text search across alert name, description, source/destination IPs
- [ ] Sort: by severity, timestamp, status
- [ ] Bulk actions: select multiple alerts, bulk investigate, bulk dismiss as FP
- [ ] Alert detail panel: slide-out with full alert JSON, MITRE mapping, related investigations
- [ ] Auto-refresh: new alerts appear at top without page reload
- [ ] Statistics bar: counts by severity, open vs resolved
- [ ] One-click investigate: create investigation directly from alert card

#### Technical Notes

- Use existing `GET /api/v1/siem-alerts` endpoint (add filter query params)
- Bulk investigate: call `POST /api/v1/tasks/bulk` (#12)
- Real-time updates via SSE (#19) for new alerts

---

## M4: Integrations

### Issue #24: Slack integration — investigation notifications and approvals

**Priority:** High | **Milestone:** M4: Integrations | **Labels:** backend, integration, priority:high

#### Description

SOC teams live in Slack. HYDRA should push investigation completions, approval requests, and critical findings to Slack channels. Enable approvals directly from Slack via interactive messages.

#### Acceptance Criteria

- [ ] Slack app configuration: `HYDRA_SLACK_BOT_TOKEN`, `HYDRA_SLACK_SIGNING_SECRET`
- [ ] Notification types: investigation completed (with verdict), approval requested, critical finding, self-healing event
- [ ] Channel routing: configurable per tenant in settings (default channel, critical channel)
- [ ] Rich message format: investigation summary card with verdict, confidence, entities, link to dashboard
- [ ] Interactive approvals: "Approve" / "Reject" buttons on approval request messages
- [ ] `/hydra investigate <alert>` slash command: trigger investigation from Slack
- [ ] `/hydra status` slash command: show active investigations count
- [ ] Thread replies: follow-up steps posted as thread replies to original notification
- [ ] `POST /api/v1/integrations/slack/webhook` — Slack events/interactions endpoint

#### Technical Notes

- Use Slack Bolt for Go (`slack-go/slack`)
- Interactive messages: Slack sends POST to our webhook on button click
- Store Slack channel mapping in `tenants.settings` JSONB: `{"slack": {"channel": "#soc-alerts"}}`

---

### Issue #25: Jira integration — automatic ticket creation from verdicts

**Priority:** High | **Milestone:** M4: Integrations | **Labels:** backend, integration, priority:high

#### Description

SOAR response playbook has `ticket` action type but it's a stub (`NotImplementedError`). Implement Jira Cloud integration to auto-create incident tickets when investigations find true positives.

#### Acceptance Criteria

- [ ] Jira configuration per tenant: `jira_url`, `jira_email`, `jira_api_token`, `jira_project_key`
- [ ] Auto-create ticket when investigation verdict = `true_positive` and playbook includes `ticket` action
- [ ] Ticket fields: summary (alert name), description (investigation report markdown), priority (mapped from severity), labels (MITRE techniques), custom fields (investigation_id, entity list)
- [ ] Bi-directional sync: ticket status changes in Jira update HYDRA response execution status
- [ ] `POST /api/v1/integrations/jira/test` — Test connection with provided credentials
- [ ] Webhook receiver: `POST /api/v1/integrations/jira/webhook` for Jira status change events
- [ ] Dashboard: Jira ticket link shown on investigation detail page
- [ ] Implement `ticket` action handler in `worker/response/actions.py` (replace `NotImplementedError`)

#### Technical Notes

- Jira Cloud REST API v3: `POST /rest/api/3/issue`
- Auth: email + API token (Basic auth)
- Store credentials encrypted in `tenants.settings`
- Priority mapping: critical→Highest, high→High, medium→Medium, low→Low

---

### Issue #26: Microsoft Teams integration — adaptive card notifications

**Priority:** Medium | **Milestone:** M4: Integrations | **Labels:** backend, integration, priority:medium

#### Description

Many enterprise SOCs use Microsoft Teams. Add Teams webhook integration for investigation notifications using Adaptive Cards for rich formatting.

#### Acceptance Criteria

- [ ] Teams incoming webhook URL configuration per tenant
- [ ] Adaptive Card format: investigation summary with verdict badge, entity table, action buttons
- [ ] Notification types: investigation completed, approval requested, critical alert received
- [ ] Action buttons: link to dashboard investigation page
- [ ] `POST /api/v1/integrations/teams/test` — Send test card to configured webhook
- [ ] Fallback: plain text message if Adaptive Card rendering fails

#### Technical Notes

- Teams incoming webhooks accept POST with Adaptive Card JSON
- No bot framework needed — simple HTTP POST to webhook URL
- Adaptive Card Designer (adaptivecards.io) for card template creation

---

### Issue #27: VirusTotal integration — automated IOC enrichment

**Priority:** High | **Milestone:** M4: Integrations | **Labels:** backend, worker, priority:high

#### Description

HYDRA extracts entities (IPs, domains, file hashes) but doesn't check them against threat intelligence feeds. Integrate VirusTotal API to auto-enrich IOCs during investigation.

#### Acceptance Criteria

- [ ] New activity: `enrich_ioc_virustotal` — check IP, domain, or hash against VT
- [ ] VT API v3: `/api/v3/ip_addresses/{ip}`, `/api/v3/domains/{domain}`, `/api/v3/files/{hash}`
- [ ] Extract: detection ratio, reputation score, WHOIS data, SSL cert info, community votes
- [ ] Store enrichment in `entities` table: `enrichment_data` JSONB column
- [ ] Rate limiting: VT free tier = 4 req/min; queue and throttle
- [ ] Cache: store VT results in Redis (24h TTL) to avoid duplicate lookups
- [ ] Integration into `ExecuteTaskWorkflow`: enrich entities after extraction step
- [ ] Dashboard: show VT reputation badge on entity in investigation view
- [ ] Configuration: `VIRUSTOTAL_API_KEY` environment variable (optional — skip if not set)

#### Technical Notes

- VT API rate limits are strict on free tier — implement Redis-based token bucket
- Batch lookup not available on free tier — queue individual requests
- Premium tier: 1000 req/min, private scanning — support via config flag

---

### Issue #28: AbuseIPDB integration — IP reputation scoring

**Priority:** Medium | **Milestone:** M4: Integrations | **Labels:** backend, worker, priority:medium

#### Description

Complement VirusTotal with AbuseIPDB for IP-specific threat intelligence. AbuseIPDB provides abuse confidence scores, country data, and report history for IP addresses.

#### Acceptance Criteria

- [ ] New activity: `enrich_ip_abuseipdb` — check IP against AbuseIPDB
- [ ] API v2: `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90`
- [ ] Extract: abuse confidence score (0-100), total reports, country, ISP, usage type, domain
- [ ] Store in `entities.enrichment_data` JSONB alongside VT data
- [ ] Rate limiting: free tier = 1000 checks/day; track daily usage in Redis
- [ ] Bulk check support: `POST /api/v2/bulk-report` for batch enrichment
- [ ] Dashboard: abuse score badge (green <25, yellow 25-75, red >75) on IP entities
- [ ] Configuration: `ABUSEIPDB_API_KEY` environment variable

---

### Issue #29: Email notifications — investigation digest and approval alerts

**Priority:** Medium | **Milestone:** M4: Integrations | **Labels:** backend, priority:medium

#### Description

Not all analysts are in Slack or watching the dashboard. Critical findings and approval requests should be delivered via email with formatted investigation summaries.

#### Acceptance Criteria

- [ ] SMTP configuration: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
- [ ] Email types: investigation completed (with verdict), approval requested (with approve link), daily digest
- [ ] HTML email template: branded, investigation summary, entity table, action links
- [ ] Daily digest: summary of investigations completed, alerts triaged, pending approvals (sent at configurable time)
- [ ] User preferences: per-user email notification settings (all, critical only, digest only, none)
- [ ] Approval via email: magic link to approve/reject (signed URL, 24h expiry)
- [ ] Unsubscribe link in all emails
- [ ] `POST /api/v1/integrations/email/test` — Send test email

#### Technical Notes

- Use Go `net/smtp` or `go-mail/mail` library
- HTML templates: Go `html/template` with inline CSS (email clients strip `<style>`)
- Signed approval URLs: HMAC-SHA256 with approval_id + user_id + timestamp

---

### Issue #30: ServiceNow ITSM integration — incident management

**Priority:** Medium | **Milestone:** M4: Integrations | **Labels:** backend, integration, priority:medium

#### Description

Enterprise customers use ServiceNow for incident management. Implement bi-directional integration: auto-create incidents from HYDRA verdicts, sync status updates back.

#### Acceptance Criteria

- [ ] ServiceNow configuration: instance URL, username, password (or OAuth)
- [ ] Auto-create incident: `POST /api/now/table/incident` on true_positive verdict
- [ ] Field mapping: short_description, description (investigation report), urgency, impact, assignment_group, category
- [ ] Bi-directional: ServiceNow incident state changes update HYDRA response execution
- [ ] Webhook: ServiceNow business rule triggers HYDRA update on incident close
- [ ] `POST /api/v1/integrations/servicenow/test` — Test connection
- [ ] Dashboard: ServiceNow incident link on investigation detail page
- [ ] Implement `ticket` action handler for ServiceNow variant

---

### Issue #31: Webhook event catalog and developer documentation

**Priority:** Medium | **Milestone:** M4: Integrations | **Labels:** backend, documentation, priority:medium

#### Description

HYDRA supports outgoing webhooks but the event types, payloads, and signatures are not documented. Create a developer-facing webhook event catalog for custom integrations.

#### Acceptance Criteria

- [ ] Document all webhook event types: `investigation.completed`, `alert.received`, `approval.requested`, `approval.decided`, `response.executed`, `self_healing.event`
- [ ] Payload schemas for each event type (JSON Schema)
- [ ] Signature verification guide (HMAC-SHA256 with `X-Webhook-Signature` header)
- [ ] Retry policy documentation: 3 attempts, exponential backoff
- [ ] Webhook testing tool: `POST /api/v1/webhooks/test` — send sample event to configured endpoint
- [ ] Event replay: `POST /api/v1/webhooks/replay/:delivery_id` — resend a failed delivery
- [ ] Dashboard: webhook delivery log with status, response code, retry count
- [ ] Example code: Python, Node.js, Go webhook receivers

---

## M5: Intelligence & RAG

### Issue #32: pgvector index optimization — HNSW indexes for entity search

**Priority:** Critical | **Milestone:** M5: Intelligence & RAG | **Labels:** backend, performance, priority:critical

#### Description

Entity similarity search uses `<->` operator on `entities.embedding` (768-dim) without any vector index. With 1M+ entities, queries do full table scans taking seconds. Add HNSW indexes for sub-millisecond approximate nearest neighbor search.

#### Acceptance Criteria

- [ ] Create HNSW index on `entities.embedding`: `CREATE INDEX idx_entities_embedding_hnsw ON entities USING hnsw (embedding vector_l2_ops) WITH (m=16, ef_construction=200)`
- [ ] Create HNSW index on `entity_edges.embedding`
- [ ] Create HNSW index on `agent_skills.embedding`
- [ ] Create HNSW index on `investigation_memory.embedding`
- [ ] Tune `ef_search` parameter: default 100 (balance recall vs speed)
- [ ] Benchmark: measure search latency before/after index (target: <10ms for top-10 neighbors)
- [ ] Migration: `migrations/020_vector_indexes.sql`
- [ ] Add `SET hnsw.ef_search = 100` in connection setup
- [ ] Monitor: Prometheus metric for vector search latency
- [ ] Document index maintenance: `REINDEX` schedule, vacuum recommendations

#### Technical Notes

- HNSW preferred over IVFFlat: better recall, no training step, handles inserts well
- pgvector 0.7+ required for HNSW (verify Docker image version)
- Index creation on 1M rows takes ~5 minutes — run during maintenance window
- `m=16` is good default; higher = better recall, more memory

---

### Issue #33: Semantic investigation search — RAG across past investigations

**Priority:** High | **Milestone:** M5: Intelligence & RAG | **Labels:** backend, frontend, priority:high

#### Description

HYDRA stores investigation memory with embeddings but doesn't expose semantic search to analysts. Add a "search past investigations" feature that finds similar cases using vector similarity.

#### Acceptance Criteria

- [ ] `GET /api/v1/investigations/search?q=<natural language query>` — semantic search endpoint
- [ ] Embed query using TEI (same model as entity embeddings)
- [ ] Search across `investigation_memory.embedding` + `entities.embedding`
- [ ] Return: matching investigations with similarity score, verdict, key findings
- [ ] Hybrid search: combine vector similarity with keyword matching (BM25 via `pg_trgm`)
- [ ] Filters: date range, verdict type, severity, MITRE technique
- [ ] Dashboard: search bar on main page, results as investigation cards with similarity %
- [ ] "Similar investigations" panel on task detail page (auto-populated)
- [ ] Limit: top 20 results, similarity threshold > 0.7

#### Technical Notes

- Two-stage retrieval: vector search (top 100) → rerank by BM25 keyword overlap (top 20)
- TEI endpoint: `POST /embed` with `{"inputs": "query text"}`
- Combine with existing investigation memory enrichment (reuse `investigation_memory.py` logic)

---

### Issue #34: Batch entity embedding pipeline

**Priority:** Medium | **Milestone:** M5: Intelligence & RAG | **Labels:** backend, worker, priority:medium

#### Description

Entities are embedded one-at-a-time via individual TEI API calls. For bootstrap corpus (240+ entities per batch), this is slow and wasteful. Implement batch embedding for bulk operations.

#### Acceptance Criteria

- [ ] Batch embedding function: `embed_batch(texts: list[str]) -> list[list[float]]`
- [ ] Use TEI batch endpoint: `POST /embed` with `{"inputs": ["text1", "text2", ...]}`
- [ ] Batch size: 32 texts per request (configurable)
- [ ] Retry logic: exponential backoff on TEI overload (503)
- [ ] Use batch embedding in: `write_entity_graph`, `bootstrap.process_entity`, `embed_investigation`
- [ ] Metrics: `hydra_embedding_batch_size`, `hydra_embedding_latency_seconds`
- [ ] Fallback: single-item embedding if batch fails

#### Technical Notes

- TEI supports batch natively — just pass array of inputs
- Chunk large batches (>32) into sub-batches to stay within memory limits
- Current TEI model: nomic-embed-text-v1.5 (768-dim, 8192 token context)

---

### Issue #35: Fine-tuning evaluation metrics — BLEU, accuracy, regression testing

**Priority:** High | **Milestone:** M5: Intelligence & RAG | **Labels:** backend, worker, priority:high

#### Description

Fine-tuning pipeline exports training data and computes quality scores, but model evaluation is a stub. Add proper metrics to compare fine-tuned models against baseline before promotion.

#### Acceptance Criteria

- [ ] Evaluation metrics: token accuracy, BLEU score, verdict accuracy, code validity rate
- [ ] Holdout test set: 20% of training data reserved for evaluation (not used in training)
- [ ] Baseline comparison: evaluate fine-tuned model vs current production model on same test set
- [ ] Regression gate: fine-tuned model must score >= baseline on all metrics to be promoted
- [ ] Evaluation report: JSON with per-metric scores, examples of improvements/regressions
- [ ] Store results in `model_registry.eval_score` (JSONB with breakdown)
- [ ] A/B test integration: auto-create A/B test between baseline and fine-tuned model
- [ ] Dashboard: model performance comparison chart (admin view)

#### Technical Notes

- BLEU: use `nltk.translate.bleu_score` or implement 4-gram BLEU manually
- Code validity: `compile(code, 'test.py', 'exec')` to check syntax
- Verdict accuracy: compare predicted verdict against labeled ground truth from accuracy corpus

---

### Issue #36: Embedding versioning and re-embedding pipeline

**Priority:** Medium | **Milestone:** M5: Intelligence & RAG | **Labels:** backend, worker, priority:medium

#### Description

When the embedding model changes (e.g., nomic-embed-text-v1.5 → v2.0), existing embeddings become incompatible with new queries. Track embedding model version and support bulk re-embedding.

#### Acceptance Criteria

- [ ] Add `embedding_model` VARCHAR(100) column to all tables with embeddings
- [ ] Set `embedding_model` on every embed operation (current: `nomic-embed-text-v1.5`)
- [ ] Re-embedding workflow: `ReembedWorkflow` — process all entities/memories with new model
- [ ] Batch processing: 1000 records per batch, with progress tracking
- [ ] Version check: warn if query embedding model differs from stored embeddings
- [ ] Migration: `migrations/021_embedding_versioning.sql`
- [ ] Admin endpoint: `POST /api/v1/admin/reembed` — trigger re-embedding workflow

---

### Issue #37: Threat intelligence feed ingestion — STIX/TAXII

**Priority:** Medium | **Milestone:** M5: Intelligence & RAG | **Labels:** backend, worker, priority:medium

#### Description

HYDRA compares entities against its own investigation history but not external threat intelligence. Ingest STIX 2.1 indicators from TAXII feeds (MITRE, AlienVault OTX, CIRCL) to enrich entity lookups.

#### Acceptance Criteria

- [ ] TAXII 2.1 client: poll configured feeds on schedule (hourly)
- [ ] Parse STIX 2.1 objects: indicators (IP, domain, hash), attack patterns, campaigns
- [ ] Store in new `threat_intel_indicators` table: type, value, source, confidence, valid_from, valid_until
- [ ] Integrate into entity enrichment: check extracted entities against TI indicators
- [ ] Dashboard: threat intel match badge on entities (with source attribution)
- [ ] Feed management: `POST /api/v1/threat-intel/feeds` — add/remove TAXII feeds
- [ ] Stats: `GET /api/v1/threat-intel/stats` — indicator counts by source, type, freshness
- [ ] Deduplication: same IOC from multiple feeds stored once with source array

#### Technical Notes

- TAXII 2.1: HTTP-based, use Go `httpx` or Python `taxii2-client`
- Free feeds: MITRE ATT&CK TAXII, AlienVault OTX, CIRCL passive DNS
- STIX parsing: use `stix2` Python library in worker activity

---

### Issue #38: Investigation cache optimization — Redis + semantic dedup

**Priority:** Medium | **Milestone:** M5: Intelligence & RAG | **Labels:** backend, worker, priority:medium

#### Description

Investigation cache (`investigation_cache` table) uses SHA-256 indicator hashes with 24h TTL. Add semantic deduplication: if a very similar alert was investigated recently, return cached results instead of re-investigating.

#### Acceptance Criteria

- [ ] Semantic cache: embed incoming alert, search for similar cached investigations (threshold 0.95)
- [ ] If cache hit: return cached verdict + findings without running workflow
- [ ] Cache levels: L1 (Redis, exact match, 1h TTL), L2 (pgvector, semantic match, 24h TTL)
- [ ] Cache stats: hit rate, miss rate, average savings per hit
- [ ] Cache invalidation: `POST /api/v1/cache/invalidate` — clear specific or all cache entries
- [ ] Prometheus metrics: `hydra_cache_hits_total`, `hydra_cache_misses_total`, `hydra_cache_savings_seconds`
- [ ] Dashboard: cache performance panel (hit rate %, estimated time saved)
- [ ] Bypass flag: `force_reinvestigate=true` in task creation to skip cache

---

## M6: Testing & Quality

### Issue #39: End-to-end test suite with docker-compose

**Priority:** High | **Milestone:** M6: Testing & Quality | **Labels:** testing, priority:high

#### Description

No E2E tests exist that verify the complete flow: API receives alert → Temporal schedules workflow → worker generates code → sandbox executes → results returned. Integration tests exist but run inside the worker container only. Build an E2E suite that exercises the full stack.

#### Acceptance Criteria

- [ ] E2E test framework: Python script that runs against live docker-compose stack
- [ ] Setup: `docker compose up -d`, wait for health checks, seed test data
- [ ] Test cases:
  - Submit task via API → verify status transitions (pending → running → completed)
  - Submit SIEM alert via webhook → verify investigation auto-triggered
  - Upload file → verify task created with file content
  - Approval flow: submit high-risk task → verify approval request created → approve → verify completion
  - Playbook resolution: submit alert matching playbook → verify correct playbook selected
  - Entity extraction: verify entities written to entity graph
  - Investigation memory: submit duplicate alert → verify enrichment from prior investigation
- [ ] Teardown: clean up test data, optionally `docker compose down`
- [ ] CI integration: run E2E tests on PR merge to master (not on every push — too slow)
- [ ] Timeout: 5 minutes max for full suite
- [ ] Report: JUnit XML output for CI visualization

#### Technical Notes

- Use Python `requests` + `pytest` for test runner
- Wait for Temporal workflow completion: poll task status with backoff
- Test data: dedicated tenant `e2e-test` with known credentials
- Directory: `tests/e2e/`

---

### Issue #40: Mock LLM server for offline testing

**Priority:** High | **Milestone:** M6: Testing & Quality | **Labels:** testing, priority:high

#### Description

All tests require a running vLLM instance (GPU). This blocks CI on CPU-only runners and makes tests non-deterministic. Create a mock LLM server that returns canned responses for known prompts.

#### Acceptance Criteria

- [ ] Mock server: Python Flask/FastAPI app implementing OpenAI-compatible `/v1/chat/completions` and `/v1/embeddings`
- [ ] Response modes: deterministic (same prompt → same response), random (realistic token counts)
- [ ] Canned responses: for each prompt template (code generation, entity extraction, diagnosis), pre-recorded realistic outputs
- [ ] Token counting: return realistic `usage` object (approximate counts)
- [ ] Latency simulation: configurable delay (default 100ms) to catch timeout bugs
- [ ] Error simulation: configurable error rate for testing retry logic
- [ ] Docker service: `hydra-mock-llm` in docker-compose with `--profile test`
- [ ] CI: use mock LLM instead of vLLM in GitHub Actions
- [ ] `HYDRA_LLM_MOCK=true` environment variable to route through mock

#### Technical Notes

- OpenAI API compatibility: same request/response format as vLLM
- Record real responses: `scripts/record-llm-responses.py` saves actual vLLM outputs as fixtures
- Directory: `tests/mock_llm/`

---

### Issue #41: Sandbox escape test suite

**Priority:** High | **Milestone:** M6: Testing & Quality | **Labels:** testing, security, priority:high

#### Description

HYDRA's sandbox has 4 security layers (AST prefilter, seccomp, Docker isolation, kill timer). No automated tests verify these layers block malicious code. Build a test suite that attempts sandbox escapes and verifies they're blocked.

#### Acceptance Criteria

- [ ] Test categories:
  - **Import bypass**: `__import__`, `importlib`, `eval("__imp" + "ort__")`, encoding tricks
  - **Network access**: `socket.connect()`, `urllib.request`, `http.client`, DNS resolution
  - **File system escape**: read `/etc/passwd`, write outside `/tmp`, symlink traversal
  - **Process execution**: `subprocess.Popen`, `os.system`, `os.exec*`, `ctypes.CDLL`
  - **Resource exhaustion**: fork bomb, memory allocation loop, CPU spin
  - **Information disclosure**: environment variables, container metadata
- [ ] Each test: submit code via API, verify it's blocked (by AST prefilter or sandbox)
- [ ] Identify which layer blocks each attempt (AST vs seccomp vs network vs timer)
- [ ] Regression test: run on every CI build
- [ ] Report: matrix of attack → blocked/allowed → which layer
- [ ] At least 30 distinct escape attempts

#### Technical Notes

- Run as E2E tests against live stack (sandbox container must be running)
- AST prefilter catches most attacks before execution — test both prefilter alone and full sandbox
- Directory: `tests/security/`

---

### Issue #42: Code coverage tracking with pytest-cov

**Priority:** Medium | **Milestone:** M6: Testing & Quality | **Labels:** testing, priority:medium

#### Description

No code coverage measurement exists. Add pytest-cov to track test coverage for the Python worker and enforce minimum thresholds in CI.

#### Acceptance Criteria

- [ ] Add `pytest-cov` to worker requirements
- [ ] Coverage configuration in `pyproject.toml` or `.coveragerc`
- [ ] CI: generate coverage report on every PR
- [ ] Minimum threshold: 40% initially (increase over time)
- [ ] Coverage report: HTML report uploaded as CI artifact
- [ ] Badge: coverage percentage in README
- [ ] Exclude from coverage: test files, migrations, __init__.py, type stubs
- [ ] Branch coverage: track both line and branch coverage

---

### Issue #43: Load test automation in CI — performance regression gate

**Priority:** Medium | **Milestone:** M6: Testing & Quality | **Labels:** testing, performance, priority:medium

#### Description

Load tests exist (`scripts/load_testing/`) but run manually. Automate them in CI to catch performance regressions. Current baseline: 17 invocations/min (single worker).

#### Acceptance Criteria

- [ ] CI job: run load test on master merges (not every PR)
- [ ] Metrics collected: throughput (inv/min), p50/p95/p99 latency, error rate
- [ ] Regression gate: fail if throughput drops >20% from baseline or error rate >5%
- [ ] Baseline stored in `tests/benchmarks/baseline.json` (updated manually after confirmed improvements)
- [ ] Results: published as CI artifact (JSON + chart)
- [ ] Comparison: current run vs baseline in PR comment
- [ ] Environment: dedicated docker-compose with mock LLM (#40) for consistency

---

### Issue #44: Accuracy validation in CI — 50-alert corpus gate

**Priority:** High | **Milestone:** M6: Testing & Quality | **Labels:** testing, priority:high

#### Description

50 labeled alerts exist in `worker/tests/accuracy/` but the validation runner doesn't compute metrics or gate CI. Wire accuracy testing into CI to catch LLM regression.

#### Acceptance Criteria

- [ ] Run accuracy validation on master merges
- [ ] Metrics: verdict accuracy (correct/total), false positive rate, false negative rate, avg confidence
- [ ] Gate: fail if accuracy drops below 70% (configurable threshold)
- [ ] Per-category breakdown: accuracy by alert type (brute_force, c2, phishing, etc.)
- [ ] Results: JSON report with per-alert predictions vs ground truth
- [ ] Confusion matrix: TP, FP, TN, FN counts
- [ ] Dashboard: accuracy trend chart (admin view) from historical runs
- [ ] Expand corpus: add 10 new labeled alerts per sprint

---

## M7: Deployment & Scale

### Issue #45: Container registry — automated Docker image builds

**Priority:** High | **Milestone:** M7: Deployment & Scale | **Labels:** deployment, priority:high

#### Description

CI builds Docker images but doesn't push them to a registry. Deployments require building from source. Push versioned images to GitHub Container Registry (ghcr.io) for reproducible deployments.

#### Acceptance Criteria

- [ ] Push images to `ghcr.io/7inaydas-cmyk/hydra-mvp/{service}:{tag}`
- [ ] Services: `api`, `worker`, `dashboard`, `mock-llm`
- [ ] Tags: `latest` (master), `v{semver}` (tags), `sha-{commit}` (every build)
- [ ] Multi-platform: `linux/amd64` (add `linux/arm64` later for Mac M-series)
- [ ] CI: push on master merge and tag creation
- [ ] Image scanning: `trivy` vulnerability scan before push (fail on critical CVEs)
- [ ] Size optimization: multi-stage builds, .dockerignore, minimal base images
- [ ] Update `docker-compose.yml` to reference registry images (with local build fallback)

#### Technical Notes

- GitHub Actions: `docker/build-push-action@v5` with `ghcr.io` login
- Worker image is largest (~2GB with Python + ML deps) — optimize layers
- Dashboard: Vite build → nginx static serve (~50MB final image)

---

### Issue #46: Helm chart for Kubernetes deployment

**Priority:** Medium | **Milestone:** M7: Deployment & Scale | **Labels:** deployment, priority:medium

#### Description

K8s deployment uses Kustomize with 3 overlays (dev/prod/airgap). Helm is the de facto Kubernetes package manager and provides better templating, release management, and values override. Create a Helm chart for simpler deployments.

#### Acceptance Criteria

- [ ] Helm chart: `helm/hydra/` directory
- [ ] `values.yaml`: all configurable parameters with sane defaults
- [ ] Templates: Deployments (api, worker, dashboard), StatefulSets (postgres, redis), Services, Ingress, ConfigMaps, Secrets, HPA, NetworkPolicy, PVC
- [ ] Sub-charts: PostgreSQL (bitnami), Redis (bitnami) as optional dependencies
- [ ] `helm install hydra ./helm/hydra -f values-prod.yaml`
- [ ] Values files: `values-dev.yaml`, `values-prod.yaml`, `values-airgap.yaml`
- [ ] Chart tests: `helm test hydra` runs health checks
- [ ] Documentation: `helm/hydra/README.md` with parameter table
- [ ] Publish to chart repository (GitHub Pages or OCI registry)

---

### Issue #47: Blue-green deployment automation

**Priority:** Medium | **Milestone:** M7: Deployment & Scale | **Labels:** deployment, priority:medium

#### Description

Updating HYDRA requires `docker compose down` + `up`, causing downtime. Implement blue-green deployment for zero-downtime updates, especially for the API and worker services.

#### Acceptance Criteria

- [ ] `scripts/deploy-blue-green.sh` — orchestrate blue-green switch
- [ ] Deploy new version alongside current (different container names)
- [ ] Health check new version before switching traffic
- [ ] Reverse proxy (Caddy/Traefik) switches upstream to new version
- [ ] Workers: graceful drain (finish current workflows, stop accepting new ones)
- [ ] Rollback: one-command switch back to previous version if new version fails
- [ ] Database migrations: run before switching traffic (backward-compatible migrations only)
- [ ] Kubernetes: use Deployment `strategy.type: RollingUpdate` with `maxSurge: 1, maxUnavailable: 0`

---

### Issue #48: Multi-region deployment architecture

**Priority:** Low | **Milestone:** M7: Deployment & Scale | **Labels:** deployment, architecture, priority:low

#### Description

HYDRA currently assumes single-region deployment. For global SOC teams, design a multi-region architecture with data residency controls and low-latency access.

#### Acceptance Criteria

- [ ] Architecture document: multi-region topology (active-active vs active-passive)
- [ ] Data residency: tenant data stays in configured region (EU, US, APAC)
- [ ] Database: PostgreSQL logical replication between regions
- [ ] API: global load balancer routing to nearest region
- [ ] Temporal: per-region Temporal clusters with cross-region task routing
- [ ] Object storage: MinIO/S3 replication across regions
- [ ] Configuration: `HYDRA_REGION=us-east-1` environment variable
- [ ] Tenant config: `data_region` field determining where data is stored
- [ ] Document trade-offs: consistency vs latency, compliance implications

---

### Issue #49: Disaster recovery runbook and automated failover

**Priority:** High | **Milestone:** M7: Deployment & Scale | **Labels:** deployment, documentation, priority:high

#### Description

No disaster recovery plan exists. If the primary server fails, there's no documented procedure to restore service. Create a runbook and automate critical recovery steps.

#### Acceptance Criteria

- [ ] DR runbook document: `docs/DISASTER_RECOVERY.md`
- [ ] Recovery scenarios: server crash, database corruption, network partition, GPU failure
- [ ] RPO (Recovery Point Objective): 1 hour (hourly backups from #6)
- [ ] RTO (Recovery Time Objective): 30 minutes (automated restore)
- [ ] `scripts/disaster-recovery.sh` — automated restore from latest MinIO backup
- [ ] Verify restore: spin up temp stack, validate data integrity, report
- [ ] GPU failure scenario: automatic fallback to Ollama/CPU inference (air-gap mode)
- [ ] Temporal recovery: workflow execution history preserved in PostgreSQL
- [ ] Communication template: incident status page updates during DR
- [ ] DR drill: quarterly test procedure (document results)

---

### Issue #50: Infrastructure as Code — Terraform modules

**Priority:** Low | **Milestone:** M7: Deployment & Scale | **Labels:** deployment, priority:low

#### Description

Cloud deployments are manual. Create Terraform modules for AWS/GCP/Azure that provision the complete HYDRA stack (VPC, compute, RDS, ElastiCache, S3, ECR, EKS).

#### Acceptance Criteria

- [ ] Terraform module: `terraform/aws/` — complete AWS deployment
- [ ] Resources: VPC, subnets, security groups, EKS cluster, RDS PostgreSQL, ElastiCache Redis, S3 bucket, ECR repository, ALB, Route53
- [ ] GPU support: EC2 `g4dn.xlarge` for vLLM inference (or Lambda for cost optimization)
- [ ] Variables: region, instance types, domain name, CIDR ranges
- [ ] Outputs: API URL, dashboard URL, database endpoint, monitoring URLs
- [ ] State management: S3 backend with DynamoDB locking
- [ ] Cost estimate: `terraform plan` output includes estimated monthly cost
- [ ] Destroy: `terraform destroy` cleanly removes all resources
- [ ] Document: `terraform/README.md` with quickstart

---

## M8: Workflow Automation

### Issue #51: Auto-trigger response playbooks on investigation completion

**Priority:** High | **Milestone:** M8: Workflow Automation | **Labels:** backend, worker, priority:high

#### Description

`ResponsePlaybookWorkflow` exists but is never auto-triggered. When an investigation completes with `verdict=true_positive`, matching response playbooks should execute automatically. Currently requires manual API call.

#### Acceptance Criteria

- [ ] After `ExecuteTaskWorkflow` completes with `true_positive` verdict:
  - Query `response_playbooks` for matching trigger conditions (alert_type, severity)
  - Auto-start `ResponsePlaybookWorkflow` with investigation context
- [ ] Trigger matching logic: playbook `trigger_conditions` JSONB matches alert metadata
- [ ] Priority ordering: if multiple playbooks match, execute highest-priority first
- [ ] Dry-run mode: tenant setting to log what would execute without actually running
- [ ] Skip if already triggered: dedup by investigation_id + playbook_id
- [ ] Audit log: `response_auto_triggered` event type
- [ ] Dashboard: show triggered response actions on investigation detail page
- [ ] Configuration: per-tenant enable/disable auto-response in settings

#### Technical Notes

- Add workflow continuation in `ExecuteTaskWorkflow.run()` after final verdict
- Use `workflow.start_child_workflow(ResponsePlaybookWorkflow, ...)` or `workflow.execute_activity(find_matching_playbooks, ...) → start workflow`
- `find_matching_playbooks` activity already exists — wire into task completion

---

### Issue #52: Scheduled workflow execution — cron-based detection and SRE

**Priority:** High | **Milestone:** M8: Workflow Automation | **Labels:** backend, worker, priority:high

#### Description

Detection generation and SRE self-healing workflows exist but must be triggered manually. Add Temporal schedules for recurring execution.

#### Acceptance Criteria

- [ ] `DetectionGenerationWorkflow`: run daily at 03:00 UTC (configurable)
- [ ] `SelfHealingWorkflow`: run every 30 minutes (configurable) in dry-run mode
- [ ] `CrossTenantRefreshWorkflow`: run hourly to refresh materialized views
- [ ] Schedule management: `POST /api/v1/schedules` — create/update/delete Temporal schedules
- [ ] `GET /api/v1/schedules` — list active schedules with next run time
- [ ] Pause/resume: `POST /api/v1/schedules/:id/pause` and `/resume`
- [ ] Schedule configuration in `tenants.settings`: `{"schedules": {"sre": "*/30 * * * *", "detection": "0 3 * * *"}}`
- [ ] Dashboard: schedule management page (admin) showing active schedules, last run, next run

#### Technical Notes

- Temporal Schedules API: `client.create_schedule(schedule_id, schedule, action, ...)`
- Use Temporal's built-in cron scheduling (not external cron)
- Default schedules created on worker startup if not existing

---

### Issue #53: Alert correlation engine — group related alerts into incidents

**Priority:** High | **Milestone:** M8: Workflow Automation | **Labels:** backend, worker, priority:high

#### Description

Each SIEM alert creates a separate investigation. Related alerts (same source IP, same timeframe, same attack pattern) should be correlated into a single incident for holistic investigation.

#### Acceptance Criteria

- [ ] Correlation rules: same source_ip within 15min, same MITRE technique within 1h, same entity cluster
- [ ] New `incidents` table: id, tenant_id, title, severity, status, alert_ids, investigation_ids, created_at
- [ ] Correlation activity: on new alert, check for matching open incidents
- [ ] If match: add alert to existing incident, enrich investigation context
- [ ] If no match: create new incident with single alert
- [ ] Incident escalation: if incident alert count exceeds threshold, upgrade severity
- [ ] Dashboard: incident list page, incident detail showing all correlated alerts
- [ ] API: `GET /api/v1/incidents`, `GET /api/v1/incidents/:id`, `POST /api/v1/incidents/:id/merge`
- [ ] Investigation context: correlated alerts provide additional context to LLM prompt

#### Technical Notes

- Correlation window: configurable per tenant
- Entity-based correlation: if alerts share entities (IP, domain), correlate
- Use `entities` table and edge relationships for graph-based correlation

---

### Issue #54: Investigation SLA monitoring and escalation

**Priority:** Medium | **Milestone:** M8: Workflow Automation | **Labels:** backend, priority:medium

#### Description

No SLA tracking exists for investigation completion times. Add configurable SLAs per severity level with automatic escalation when breached.

#### Acceptance Criteria

- [ ] SLA configuration per tenant: `{"sla": {"critical": "15m", "high": "1h", "medium": "4h", "low": "24h"}}`
- [ ] SLA tracking: monitor `agent_tasks` for tasks exceeding their SLA
- [ ] Escalation actions on breach: notification (Slack/email), priority boost, reassignment
- [ ] SLA status: `within_sla`, `warning` (80% elapsed), `breached`
- [ ] Dashboard: SLA compliance widget (% within SLA by severity)
- [ ] API: `GET /api/v1/sla/compliance` — SLA metrics over time period
- [ ] Prometheus metrics: `hydra_sla_breached_total{severity}`, `hydra_sla_compliance_ratio`
- [ ] Scheduled check: every 5 minutes, scan for SLA warnings and breaches

---

### Issue #55: Auto-retrain trigger — accuracy-driven model update

**Priority:** Medium | **Milestone:** M8: Workflow Automation | **Labels:** backend, worker, priority:medium

#### Description

Fine-tuning pipeline exists but never auto-triggers. When investigation accuracy drops below threshold (measured by analyst feedback), automatically trigger data export, quality scoring, and model evaluation.

#### Acceptance Criteria

- [ ] Accuracy monitor: weekly check of verdict accuracy from `investigation_feedback` table
- [ ] Trigger threshold: if accuracy < 75% over last 100 investigations, start fine-tuning pipeline
- [ ] Guard: max 1 fine-tuning run per week (prevent thrashing)
- [ ] Pipeline: export training data → quality score → evaluate → compare vs baseline → promote if better
- [ ] Notification: alert admin when auto-retrain triggered (with accuracy metrics)
- [ ] Audit: log auto-retrain events with before/after accuracy
- [ ] Rollback: if fine-tuned model performs worse, auto-revert to previous model
- [ ] Dashboard: model accuracy trend chart, retrain history

#### Technical Notes

- Use Temporal schedule for weekly accuracy check
- Fine-tuning evaluation depends on #35 (evaluation metrics)
- Model promotion uses existing `model_registry` + A/B test infrastructure

---

## Summary

| Milestone | Issues | Priority Breakdown |
|-----------|--------|--------------------|
| M1: Production Foundation | #1–#7 | 2 critical, 4 high, 1 medium |
| M2: API & SDK | #8–#14 | 4 high, 2 medium, 1 low |
| M3: Dashboard Evolution | #15–#23 | 4 high, 4 medium, 1 low |
| M4: Integrations | #24–#31 | 3 high, 4 medium, 1 medium |
| M5: Intelligence & RAG | #32–#38 | 1 critical, 2 high, 4 medium |
| M6: Testing & Quality | #39–#44 | 3 high, 2 medium, 1 high |
| M7: Deployment & Scale | #45–#50 | 2 high, 2 medium, 2 low |
| M8: Workflow Automation | #51–#55 | 3 high, 2 medium |
| **Total** | **55** | **3 critical, 22 high, 19 medium, 4 low** |
