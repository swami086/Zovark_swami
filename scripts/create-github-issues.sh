#!/bin/bash
# ZOVARK MVP — Bulk GitHub Issue Creator
# Usage: ./scripts/create-github-issues.sh [milestone_filter]
# Example: ./scripts/create-github-issues.sh M1
# Requires: gh CLI authenticated (gh auth login)

set -euo pipefail

REPO="7inaydas-cmyk/zovark-mvp"
DRY_RUN="${DRY_RUN:-false}"
MILESTONE_FILTER="${1:-all}"
SLEEP_SECONDS=2  # avoid GitHub rate limits

echo "=== ZOVARK GitHub Issue Creator ==="
echo "Repo: $REPO"
echo "Milestone filter: $MILESTONE_FILTER"
echo "Dry run: $DRY_RUN"
echo ""

# Create milestones first
create_milestones() {
    echo "--- Creating milestones ---"
    local milestones=(
        "M1: Production Foundation"
        "M2: API & SDK"
        "M3: Dashboard Evolution"
        "M4: Integrations"
        "M5: Intelligence & RAG"
        "M6: Testing & Quality"
        "M7: Deployment & Scale"
        "M8: Workflow Automation"
    )
    for m in "${milestones[@]}"; do
        if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY RUN] Would create milestone: $m"
        else
            gh api repos/$REPO/milestones -f title="$m" 2>/dev/null || echo "  Milestone '$m' already exists"
            sleep 1
        fi
    done
    echo ""
}

# Create labels
create_labels() {
    echo "--- Creating labels ---"
    local labels=(
        "priority:critical|b60205|Critical priority"
        "priority:high|d93f0b|High priority"
        "priority:medium|fbca04|Medium priority"
        "priority:low|0e8a16|Low priority"
        "security|5319e7|Security related"
        "backend|0075ca|Backend / API"
        "frontend|7057ff|Frontend / Dashboard"
        "worker|006b75|Python worker"
        "deployment|bfd4f2|Deployment & infrastructure"
        "testing|d4c5f9|Testing & QA"
        "integration|1d76db|External integrations"
        "sdk|c2e0c6|SDK & client libraries"
        "documentation|0075ca|Documentation"
        "performance|ff9f1c|Performance optimization"
        "architecture|ededed|Architecture decisions"
    )
    for label_spec in "${labels[@]}"; do
        IFS='|' read -r name color desc <<< "$label_spec"
        if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY RUN] Would create label: $name ($color)"
        else
            gh label create "$name" --color "$color" --description "$desc" --repo "$REPO" 2>/dev/null || echo "  Label '$name' already exists"
            sleep 0.5
        fi
    done
    echo ""
}

# Helper to create an issue
create_issue() {
    local title="$1"
    local body="$2"
    local labels="$3"
    local milestone="$4"

    if [ "$MILESTONE_FILTER" != "all" ] && [[ "$milestone" != *"$MILESTONE_FILTER"* ]]; then
        return
    fi

    if [ "$DRY_RUN" = "true" ]; then
        echo "[DRY RUN] Would create: $title"
        echo "  Labels: $labels"
        echo "  Milestone: $milestone"
        return
    fi

    echo "Creating: $title"
    gh issue create \
        --repo "$REPO" \
        --title "$title" \
        --body "$body" \
        --label "$labels" \
        --milestone "$milestone" \
        2>&1 | tail -1

    sleep $SLEEP_SECONDS
}

# ============================================================
# M1: Production Foundation
# ============================================================

create_issue \
    "SSO/OAuth2 — OIDC provider integration" \
    "$(cat <<'BODY'
## Description

ZOVARK currently supports email/password authentication only (bcrypt + JWT). Enterprise deployments require SSO via existing identity providers (Okta, Azure AD/Entra ID, Google Workspace). Without this, no enterprise customer will adopt ZOVARK in production.

## Acceptance Criteria

- [ ] Add OIDC discovery endpoint support (`/.well-known/openid-configuration`)
- [ ] Implement authorization code flow with PKCE
- [ ] Support Google, Microsoft (Entra ID), and Okta as providers
- [ ] Environment variables: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`
- [ ] Map OIDC claims to ZOVARK roles: `admin`, `analyst`, `viewer` via configurable claim key
- [ ] Auto-provision users on first login (JIT provisioning) with tenant assignment
- [ ] Fallback to email/password when OIDC is not configured
- [ ] Update `/api/v1/auth/login` to return redirect URL for OIDC flow
- [ ] Add `/api/v1/auth/callback` endpoint to handle OIDC response
- [ ] Store `external_auth_id` in users table (column already exists)
- [ ] Update dashboard login page with "Sign in with SSO" button

## Technical Notes

- Use Go `coreos/go-oidc` library for token verification
- JWT issued by ZOVARK after OIDC validation (don't pass through provider JWT)
- Session state stored in Redis during auth flow (5-minute TTL)
- `users.external_auth_id` already exists in schema — use it for OIDC subject mapping
- Keep existing bcrypt login path for air-gap deployments
BODY
)" \
    "security,backend,priority:critical" \
    "M1: Production Foundation"

create_issue \
    "TLS termination — HTTPS enforcement for all services" \
    "$(cat <<'BODY'
## Description

All ZOVARK services communicate over plaintext HTTP on localhost. Production deployments must encrypt traffic between browser ↔ API, API ↔ LiteLLM, and API ↔ Temporal. Credentials (JWT, API keys, webhook secrets) are transmitted unencrypted.

## Acceptance Criteria

- [ ] Add Caddy or Traefik reverse proxy service to `docker-compose.yml`
- [ ] Auto-generate self-signed certs for development (mkcert)
- [ ] Let's Encrypt ACME support for production domains
- [ ] API (port 8090) accessible only via HTTPS (443)
- [ ] Dashboard (port 3000) served behind reverse proxy
- [ ] Internal services (Temporal, Postgres, Redis, LiteLLM) remain HTTP on `zovark-internal` network
- [ ] `ZOVARK_TLS_ENABLED=true` environment variable to toggle
- [ ] HSTS header on all API responses when TLS enabled
- [ ] Update dashboard API base URL to use `https://` when configured
- [ ] Document certificate setup in DEPLOYMENT_GUIDE.md

## Technical Notes

- Caddy is simplest (auto-TLS, zero-config); Traefik is more flexible (Docker labels)
- Internal network traffic stays HTTP — TLS only at ingress
- K8s overlay should use cert-manager + Ingress instead of Caddy
BODY
)" \
    "security,deployment,priority:critical" \
    "M1: Production Foundation"

create_issue \
    "Secrets management — Vault integration for credentials" \
    "$(cat <<'BODY'
## Description

ZOVARK stores all secrets in `.env` files and environment variables: `POSTGRES_PASSWORD`, `ZOVARK_LLM_KEY`, `MINIO_ROOT_PASSWORD`, webhook secrets, JWT signing key. These are visible in `docker inspect`, process environment, and logs. Production requires a proper secrets manager.

## Acceptance Criteria

- [ ] Abstract secret loading behind `secrets.Get(key)` function in Go API
- [ ] Abstract secret loading behind `get_secret(key)` function in Python worker
- [ ] Support 3 backends: environment variables (default), HashiCorp Vault, AWS Secrets Manager
- [ ] `ZOVARK_SECRETS_BACKEND=env|vault|aws` environment variable
- [ ] Vault backend: AppRole auth, KV v2 engine, `zovark/` mount path
- [ ] AWS backend: IAM role-based, no access keys in config
- [ ] Rotate database password without downtime (PgBouncer handles reconnection)
- [ ] JWT signing key rotation: support multiple active keys (JWK set)
- [ ] Remove all hardcoded secrets from `docker-compose.yml` (use `_FILE` suffix pattern)
- [ ] Add `scripts/rotate-secrets.sh` helper

## Technical Notes

- Start with `_FILE` suffix pattern (Docker secrets) for simplest production use
- Vault dev server in docker-compose for testing
- PgBouncer already handles connection pooling — password rotation is seamless
BODY
)" \
    "security,backend,priority:high" \
    "M1: Production Foundation"

create_issue \
    "Two-factor authentication (TOTP)" \
    "$(cat <<'BODY'
## Description

Admin and analyst accounts need 2FA to prevent credential theft. ZOVARK currently relies on password-only authentication. Add TOTP (Time-based One-Time Password) support compatible with Google Authenticator, Authy, and 1Password.

## Acceptance Criteria

- [ ] Add `totp_secret` (encrypted) and `totp_enabled` columns to `users` table
- [ ] `POST /api/v1/auth/2fa/setup` — Generate TOTP secret, return QR code URI
- [ ] `POST /api/v1/auth/2fa/verify` — Verify TOTP code and enable 2FA
- [ ] `POST /api/v1/auth/2fa/disable` — Disable 2FA (requires current TOTP code)
- [ ] Login flow: if `totp_enabled=true`, require TOTP code after password verification
- [ ] Generate 10 backup recovery codes on setup (stored hashed)
- [ ] Rate-limit TOTP verification: 5 attempts per 5 minutes
- [ ] Dashboard: 2FA setup page in user settings with QR code display
- [ ] Admins can enforce 2FA for all users in tenant settings

## Technical Notes

- Use `pquerna/otp` library in Go for TOTP generation/verification
- 30-second window, 6-digit codes, SHA1 algorithm (Google Authenticator compatible)
- Encrypt `totp_secret` at rest using AES-256-GCM with key from secrets manager
BODY
)" \
    "security,backend,frontend,priority:high" \
    "M1: Production Foundation"

create_issue \
    "API key authentication for machine-to-machine access" \
    "$(cat <<'BODY'
## Description

External systems (SIEM, ticketing, custom scripts) need to call ZOVARK's API without user JWT tokens. Add API key support with per-key permissions, rate limits, and audit logging.

## Acceptance Criteria

- [ ] New `api_keys` table: id, tenant_id, name, key_hash (SHA-256), prefix (first 8 chars), permissions (JSONB), rate_limit, last_used_at, expires_at, created_by, created_at
- [ ] `POST /api/v1/api-keys` — Create key (returns full key once, stores hash only)
- [ ] `GET /api/v1/api-keys` — List keys (prefix only, never full key)
- [ ] `DELETE /api/v1/api-keys/:id` — Revoke key
- [ ] Accept `X-API-Key` header on all endpoints (alternative to Bearer JWT)
- [ ] Per-key permissions: `tasks:read`, `tasks:write`, `alerts:write`, `admin:*`
- [ ] Per-key rate limit override (default: 300 req/min)
- [ ] Audit log entries include `api_key_id` when used
- [ ] Key format: `zovark_sk_` prefix + 32 random bytes (base62 encoded)
- [ ] Keys scoped to single tenant (multi-tenant isolation preserved)

## Technical Notes

- Store SHA-256 hash of key, never plaintext
- Prefix (`zovark_sk_abc12345`) stored separately for identification in lists
- Auth middleware: check `X-API-Key` first, then `Authorization: Bearer` JWT
- Migration: `migrations/020_api_keys.sql`
BODY
)" \
    "security,backend,priority:high" \
    "M1: Production Foundation"

create_issue \
    "Database backup automation with S3/MinIO snapshots" \
    "$(cat <<'BODY'
## Description

PostgreSQL data is stored on Docker volumes with no backup strategy. A disk failure loses all investigations, entities, and configuration. Implement automated pg_dump to MinIO (already running) with retention policies.

## Acceptance Criteria

- [ ] New service `zovark-backup` in docker-compose (lightweight Alpine + pg_dump + mc)
- [ ] Schedule: daily full backup at 02:00 UTC, hourly WAL archiving
- [ ] Store backups in MinIO bucket `zovark-backups/` with date-prefixed paths
- [ ] Retention: 7 daily, 4 weekly, 3 monthly snapshots (oldest auto-deleted)
- [ ] `scripts/backup.sh` — Manual backup trigger
- [ ] `scripts/restore.sh` — Point-in-time recovery from MinIO snapshot
- [ ] Backup encryption: AES-256 with key from secrets config
- [ ] Backup verification: restore to temp DB, verify table counts, delete
- [ ] Health check: alert if last successful backup > 25 hours ago
- [ ] Prometheus metric: `zovark_backup_last_success_timestamp`

## Technical Notes

- Use `pg_dump --format=custom` for compression and selective restore
- MinIO already running on port 9000/9001 — reuse existing instance
- WAL archiving requires `archive_mode=on` in postgresql.conf
BODY
)" \
    "deployment,backend,priority:high" \
    "M1: Production Foundation"

create_issue \
    "Audit log export and SIEM forwarding" \
    "$(cat <<'BODY'
## Description

Audit events are stored in PostgreSQL `audit_events` table only. Compliance requires forwarding audit logs to external SIEM (Splunk, Elastic) and archival to object storage. Currently no export mechanism exists.

## Acceptance Criteria

- [ ] `GET /api/v1/audit/export` — Download audit logs as JSONL (date range filter, max 10k records)
- [ ] Syslog forwarding: configure `ZOVARK_SYSLOG_TARGET=tcp://splunk:514` to stream events
- [ ] CEF format support (Common Event Format) for SIEM compatibility
- [ ] S3/MinIO archival: daily export of audit_events older than 30 days
- [ ] Retention policy: delete archived events from DB after S3 confirmation
- [ ] Include all event types: login, task creation, approval, self-healing, injection detected
- [ ] Tamper detection: HMAC chain on exported logs (each entry signs previous hash)
- [ ] Dashboard: audit log viewer with search, filter by event_type, date range, actor

## Technical Notes

- Use Go `log/syslog` package for syslog forwarding
- CEF format: `CEF:0|ZOVARK|SOC-Agent|1.0|event_type|description|severity|extension`
- Batch export to avoid memory issues (stream rows, don't load all into memory)
BODY
)" \
    "security,backend,priority:medium" \
    "M1: Production Foundation"

# ============================================================
# M2: API & SDK
# ============================================================

create_issue \
    "OpenAPI 3.1 specification with Swagger UI" \
    "$(cat <<'BODY'
## Description

ZOVARK has 44+ API endpoints documented only in markdown files. No interactive API explorer exists. Generate an OpenAPI 3.1 spec from Go handlers and serve Swagger UI for developers.

## Acceptance Criteria

- [ ] Generate `openapi.yaml` from Go handler annotations (use `swaggo/swag` or hand-write)
- [ ] Serve Swagger UI at `/api/docs` (embed swagger-ui-dist)
- [ ] Document all 44+ endpoints: paths, methods, parameters, request/response bodies, auth requirements
- [ ] Include schema definitions for all request/response types
- [ ] Auth schemes: Bearer JWT and API Key
- [ ] Example values for all fields (realistic SOC data)
- [ ] Error response schemas: `{error: {code, message, details}}`
- [ ] Validate spec with `swagger-cli validate openapi.yaml` in CI
- [ ] Version header: `X-API-Version: 1.0.0`

## Technical Notes

- `swaggo/swag` generates from Go comments (`// @Summary`, `// @Param`, etc.)
- Alternatively, hand-write YAML and validate — more control, less coupling
- Swagger UI served as static files behind the Go server
BODY
)" \
    "backend,documentation,priority:high" \
    "M2: API & SDK"

create_issue \
    "Consistent API response envelope and error format" \
    "$(cat <<'BODY'
## Description

API responses use inconsistent formats: some return raw data, others wrap in objects. Error responses vary between handlers. Standardize all responses into a predictable envelope.

## Acceptance Criteria

- [ ] Success responses: `{"data": {...}, "meta": {"request_id": "...", "timestamp": "..."}}`
- [ ] List responses: `{"data": [...], "meta": {"total": N, "page": N, "per_page": N, "request_id": "..."}}`
- [ ] Error responses: `{"error": {"code": "VALIDATION_FAILED", "message": "...", "details": [...]}}`
- [ ] Add `X-Request-Id` header to all responses (UUID, generated per request)
- [ ] Propagate request ID through Temporal workflow execution for tracing
- [ ] Add gzip compression middleware
- [ ] Standard HTTP status codes for all handlers
- [ ] Error codes enum: `AUTH_FAILED`, `VALIDATION_FAILED`, `NOT_FOUND`, `RATE_LIMITED`, `INTERNAL_ERROR`
- [ ] Update all 44+ handlers to use envelope helpers
- [ ] Update dashboard to parse new envelope format

## Technical Notes

- Create `api/response.go` with helper functions
- Request ID generated in middleware, stored in `context.Context`
BODY
)" \
    "backend,priority:high" \
    "M2: API & SDK"

create_issue \
    "Python SDK — typed client library for ZOVARK API" \
    "$(cat <<'BODY'
## Description

Every ZOVARK integration must hand-craft HTTP calls to 44+ endpoints. A typed Python SDK reduces integration time from hours to minutes.

## Acceptance Criteria

- [ ] Package: `zovark-sdk` (publishable to PyPI)
- [ ] Typed client: `ZovarkClient(base_url, api_key=None, jwt_token=None)`
- [ ] Methods for all endpoint groups: `client.tasks.list()`, `client.tasks.create(...)`, etc.
- [ ] Response models: dataclasses for Task, Investigation, Alert, Entity, Playbook
- [ ] Async support: `AsyncZovarkClient` using `httpx.AsyncClient`
- [ ] Pagination helpers: `client.tasks.list_all()` auto-paginates
- [ ] Error handling: `ZovarkAPIError`, `ZovarkAuthError`, `ZovarkRateLimitError`
- [ ] Retry logic: exponential backoff on 429/503
- [ ] Minimal dependencies: `httpx`, `dataclasses` only
- [ ] `README.md` with quickstart and examples

## Technical Notes

- Generate from OpenAPI spec or hand-write for quality
- Directory: `sdk/python/`
- Publish as `zovark-soc-sdk`
BODY
)" \
    "sdk,priority:high" \
    "M2: API & SDK"

create_issue \
    "Per-tenant API rate limiting with Redis" \
    "$(cat <<'BODY'
## Description

ZOVARK rate-limits only auth endpoints (10 req/15min per IP). Task submission, alert ingestion, and API queries have no limits. A single tenant can exhaust worker capacity. Implement tiered, per-tenant rate limiting using Redis.

## Acceptance Criteria

- [ ] Rate limit middleware in Go API using Redis sliding window counter
- [ ] Tiers: `free` (30 req/min), `professional` (120 req/min), `enterprise` (600 req/min)
- [ ] Separate limits for: general API, task creation, webhook ingestion, bulk operations
- [ ] Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- [ ] 429 response with `Retry-After` header when exceeded
- [ ] Per-tenant override in `tenants.settings` JSONB
- [ ] Admin endpoints exempt from rate limiting
- [ ] Burst allowance: 2x limit for 10-second window
- [ ] Prometheus metrics: `zovark_api_rate_limited_total{tenant, endpoint}`

## Technical Notes

- Use Redis `MULTI`/`EXEC` for atomic sliding window
- Redis already running in stack
- Extract tenant from JWT claims in middleware
BODY
)" \
    "backend,priority:high" \
    "M2: API & SDK"

create_issue \
    "Bulk task creation endpoint" \
    "$(cat <<'BODY'
## Description

SOC teams need to investigate batches of alerts. Currently tasks are created one-at-a-time. Add bulk creation for morning triage and IR response.

## Acceptance Criteria

- [ ] `POST /api/v1/tasks/bulk` — Accept array of up to 100 task definitions
- [ ] Validate all tasks before creating any (atomic batch)
- [ ] Deduplication: skip alerts matching existing fingerprints
- [ ] Response: `{"data": {"created": [...ids], "skipped": [...reasons], "failed": [...errors]}}`
- [ ] Queue all created tasks to Temporal in parallel
- [ ] Rate limit: bulk endpoint has separate, stricter limit (10 req/min)
- [ ] Priority ordering: high-severity tasks queued first

## Technical Notes

- Use database transaction for atomic insert
- Temporal workflow starts can be parallelized with goroutines
BODY
)" \
    "backend,priority:medium" \
    "M2: API & SDK"

create_issue \
    "Investigation report export (PDF + JSON)" \
    "$(cat <<'BODY'
## Description

Investigation results are viewable only in the dashboard. Analysts need to export reports for ticketing systems, management briefings, and compliance.

## Acceptance Criteria

- [ ] `GET /api/v1/tasks/:id/report` — Accept header: `application/json`, `application/pdf`, `text/markdown`
- [ ] JSON format: structured report with findings, entities, timeline, verdict
- [ ] Markdown format: human-readable (worker already generates this)
- [ ] PDF format: styled with ZOVARK branding, syntax-highlighted code blocks
- [ ] Include: executive summary, investigation steps, entities, verdict, recommendations
- [ ] Caching: store generated report in MinIO
- [ ] Dashboard: "Download Report" button on task detail page

## Technical Notes

- PDF generation: use `chromedp` or `wkhtmltopdf` in Go
- Store in MinIO: `reports/{tenant_id}/{task_id}/report.pdf`
BODY
)" \
    "backend,priority:medium" \
    "M2: API & SDK"

create_issue \
    "Content negotiation — CSV and JSONL export for lists" \
    "$(cat <<'BODY'
## Description

All API list endpoints return JSON only. SOC teams need CSV export for Excel and JSONL for log pipelines.

## Acceptance Criteria

- [ ] Support `Accept: text/csv` on list endpoints (tasks, alerts, entities, audit logs)
- [ ] Support `Accept: application/x-ndjson` for JSONL streaming
- [ ] CSV includes header row with column names
- [ ] `?format=csv` query parameter as alternative to Accept header
- [ ] Filename header: `Content-Disposition: attachment; filename="tasks-2026-03-11.csv"`
- [ ] Date range filter: `?from=...&to=...` for export scoping
- [ ] Max export: 50,000 records (paginated streaming for larger sets)

## Technical Notes

- Use Go `encoding/csv` writer streaming directly to ResponseWriter
- JSONL: `json.NewEncoder(w).Encode(row)` per row
- Stream from database cursor — don't load all into memory
BODY
)" \
    "backend,priority:low" \
    "M2: API & SDK"

# ============================================================
# M3: Dashboard Evolution
# ============================================================

create_issue \
    "Admin panel — tenant management UI" \
    "$(cat <<'BODY'
## Description

Tenant CRUD exists via API but has no UI. Admins must use curl/Postman to manage tenants, view usage, configure settings.

## Acceptance Criteria

- [ ] Admin section at `/admin` route (guarded by role check)
- [ ] Sidebar navigation: Tenants, Users, Models, System Health
- [ ] Tenant list: table with name, slug, tier, user count, task count, status
- [ ] Tenant detail: settings editor (JSONB), usage stats, rate limit config
- [ ] Create tenant form: name, slug, tier selection, initial admin user
- [ ] User management: list users per tenant, change roles, lock/unlock accounts
- [ ] System stats: total tasks, active investigations, LLM token usage, error rate
- [ ] Activity feed: recent audit events across all tenants

## Technical Notes

- Reuse existing API endpoints (`/api/v1/tenants`, `/api/v1/audit/export`)
- Admin routes check `role === 'admin'` from JWT claims
BODY
)" \
    "frontend,priority:high" \
    "M3: Dashboard Evolution"

create_issue \
    "Approval queue UI — visual pending approvals" \
    "$(cat <<'BODY'
## Description

High-risk investigation steps require approval but are managed via API only. Analysts need a visual queue to review, approve, or reject pending actions.

## Acceptance Criteria

- [ ] Approval queue page at `/approvals`
- [ ] Card-based layout: investigation context, generated code, risk assessment
- [ ] Code viewer: syntax-highlighted with dangerous operations highlighted in red
- [ ] Context panel: investigation trigger, findings so far
- [ ] Actions: Approve, Reject (with required comment), Skip
- [ ] Real-time updates: new approvals appear without page refresh
- [ ] Notification badge: count of pending approvals in sidebar
- [ ] Approval history: past decisions with timestamps and reviewer
- [ ] Mobile-responsive: swipe to approve/reject

## Technical Notes

- Use existing `GET /api/v1/approvals/pending` and `POST /api/v1/approvals/:id/decide`
- Poll every 10 seconds (SSE later)
BODY
)" \
    "frontend,priority:high" \
    "M3: Dashboard Evolution"

create_issue \
    "LLM cost tracking dashboard" \
    "$(cat <<'BODY'
## Description

ZOVARK logs all LLM calls to `llm_call_log` table with token counts and cost estimates. This data is not visible in the dashboard.

## Acceptance Criteria

- [ ] Cost overview page at `/costs`
- [ ] Summary cards: total cost (24h, 7d, 30d), avg cost per investigation, total tokens
- [ ] Cost breakdown by model tier: fast vs standard vs reasoning (bar chart)
- [ ] Cost breakdown by activity (pie chart)
- [ ] Daily cost trend: line chart over last 30 days
- [ ] Per-investigation cost on task detail page
- [ ] Budget alerts: configurable threshold, banner when approaching limit
- [ ] Cost by tenant: admin view of per-tenant spending
- [ ] Export: CSV download of cost data

## Technical Notes

- New API endpoint: `GET /api/v1/costs/summary?period=7d`
- Aggregate from `llm_call_log` table (already has `estimated_cost_usd`)
- `investigation_costs` view already exists in DB
BODY
)" \
    "frontend,priority:high" \
    "M3: Dashboard Evolution"

create_issue \
    "Entity graph visualization" \
    "$(cat <<'BODY'
## Description

ZOVARK extracts entities and builds relationship graphs in the database. This graph is invisible to analysts. Visualize entity connections to reveal attack patterns and lateral movement.

## Acceptance Criteria

- [ ] Entity graph tab on investigation detail page
- [ ] Force-directed graph layout: entities as nodes, relationships as edges
- [ ] Node styling: color by entity type (IP=blue, domain=green, hash=orange, user=purple)
- [ ] Node size: proportional to connection count
- [ ] Edge labels: relationship type (communicates_with, resolved_to, etc.)
- [ ] Click node: show entity details (verdict, confidence, related investigations)
- [ ] Cross-investigation view: entities shared across investigations
- [ ] Zoom, pan, fullscreen support
- [ ] Export as PNG or SVG

## Technical Notes

- Use D3.js force simulation or `react-force-graph-2d`
- New API endpoint: `GET /api/v1/tasks/:id/entities` (with edges)
- Limit to 200 nodes for performance
BODY
)" \
    "frontend,priority:medium" \
    "M3: Dashboard Evolution"

create_issue \
    "Real-time investigation updates via Server-Sent Events" \
    "$(cat <<'BODY'
## Description

Investigation progress is shown by polling the API every few seconds. Implement SSE for real-time push of investigation events.

## Acceptance Criteria

- [ ] `GET /api/v1/events/stream` — SSE endpoint (text/event-stream)
- [ ] Event types: `investigation.step_started`, `investigation.step_completed`, `investigation.completed`, `approval.requested`, `alert.received`
- [ ] Filter by tenant from JWT
- [ ] Heartbeat: `:keepalive` every 30 seconds
- [ ] `Last-Event-ID` support for reconnection
- [ ] Dashboard: replace polling with SSE connection
- [ ] Fallback: revert to polling if SSE fails

## Technical Notes

- Go: use `http.Flusher` interface
- Fan-out: Redis pub/sub to distribute events across API instances
- Worker publishes to Redis channel `zovark:events:{tenant_id}`
BODY
)" \
    "backend,frontend,priority:medium" \
    "M3: Dashboard Evolution"

create_issue \
    "Investigation timeline with MITRE ATT&CK mapping" \
    "$(cat <<'BODY'
## Description

Map investigation step findings to MITRE ATT&CK techniques and display as an interactive timeline showing attack progression through the kill chain.

## Acceptance Criteria

- [ ] Timeline component on task detail page
- [ ] Steps mapped to MITRE ATT&CK tactic/technique
- [ ] Kill chain phases visualization: Reconnaissance → Initial Access → ... → Impact
- [ ] Visual indicators: which phases were observed
- [ ] Click technique: link to MITRE ATT&CK page + show evidence
- [ ] Coverage heat map: detection gaps vs observed phases
- [ ] Export: STIX 2.1 bundle of investigation findings

## Technical Notes

- MITRE mapping already in `mitre_techniques` table (691 techniques)
- Entity extraction returns technique_ids — use for mapping
BODY
)" \
    "frontend,priority:medium" \
    "M3: Dashboard Evolution"

create_issue \
    "Dark mode / light mode toggle" \
    "$(cat <<'BODY'
## Description

Dashboard is dark-theme only. Add a toggle with system preference detection.

## Acceptance Criteria

- [ ] Toggle button in header (sun/moon icon)
- [ ] Respect `prefers-color-scheme` media query on first visit
- [ ] Persist preference in localStorage
- [ ] Tailwind dark mode classes — switch `class` strategy
- [ ] Smooth transition animation (150ms)
- [ ] All components readable in both modes (check contrast ratios)
BODY
)" \
    "frontend,priority:low" \
    "M3: Dashboard Evolution"

create_issue \
    "Playbook builder UI — visual workflow editor" \
    "$(cat <<'BODY'
## Description

Response playbooks are created via API with JSON definitions. Analysts need a visual drag-and-drop editor to build response playbooks.

## Acceptance Criteria

- [ ] Playbook builder page at `/playbooks/new` and `/playbooks/:id/edit`
- [ ] Drag-and-drop canvas: add steps from palette (notify, ticket, quarantine, isolate, remediate, rollback)
- [ ] Step configuration: click step to set parameters
- [ ] Conditional branching: if verdict = true_positive → quarantine, else → close
- [ ] Trigger configuration: which alert types auto-trigger this playbook
- [ ] Preview mode: dry-run visualization
- [ ] Template library: pre-built playbooks for common scenarios

## Technical Notes

- Use `reactflow` library for node-based visual editor
- Playbook JSON schema already defined in `response/` module
BODY
)" \
    "frontend,priority:medium" \
    "M3: Dashboard Evolution"

create_issue \
    "SIEM alerts management UI with advanced filtering" \
    "$(cat <<'BODY'
## Description

SIEM alerts page exists but shows minimal data with no filtering. Analysts need efficient triage: filter by severity, source, status, date range, and keyword search.

## Acceptance Criteria

- [ ] Enhanced alerts page at `/alerts`
- [ ] Filter bar: severity, status, source, date range
- [ ] Full-text search across alert name, description, IPs
- [ ] Sort: by severity, timestamp, status
- [ ] Bulk actions: select multiple alerts, bulk investigate, bulk dismiss as FP
- [ ] Alert detail panel: slide-out with full JSON, MITRE mapping, related investigations
- [ ] Auto-refresh: new alerts appear at top without reload
- [ ] Statistics bar: counts by severity, open vs resolved
- [ ] One-click investigate: create investigation from alert card

## Technical Notes

- Add filter query params to existing `GET /api/v1/siem-alerts` endpoint
BODY
)" \
    "frontend,priority:high" \
    "M3: Dashboard Evolution"

# ============================================================
# M4: Integrations
# ============================================================

create_issue \
    "Slack integration — notifications and interactive approvals" \
    "$(cat <<'BODY'
## Description

SOC teams live in Slack. Push investigation completions, approval requests, and critical findings to Slack channels. Enable approvals directly from Slack via interactive messages.

## Acceptance Criteria

- [ ] Slack app configuration: `ZOVARK_SLACK_BOT_TOKEN`, `ZOVARK_SLACK_SIGNING_SECRET`
- [ ] Notification types: investigation completed, approval requested, critical finding, self-healing event
- [ ] Channel routing: configurable per tenant in settings
- [ ] Rich message format: investigation summary card with verdict, entities, dashboard link
- [ ] Interactive approvals: Approve/Reject buttons on approval request messages
- [ ] `/zovark investigate <alert>` slash command
- [ ] `/zovark status` slash command
- [ ] Thread replies: follow-up steps posted as thread replies
- [ ] `POST /api/v1/integrations/slack/webhook` — events endpoint

## Technical Notes

- Use `slack-go/slack` library
- Store channel mapping in `tenants.settings` JSONB
BODY
)" \
    "backend,integration,priority:high" \
    "M4: Integrations"

create_issue \
    "Jira integration — automatic ticket creation from verdicts" \
    "$(cat <<'BODY'
## Description

SOAR response playbook has `ticket` action type but it's a stub (`NotImplementedError`). Implement Jira Cloud integration to auto-create incident tickets.

## Acceptance Criteria

- [ ] Jira configuration per tenant: `jira_url`, `jira_email`, `jira_api_token`, `jira_project_key`
- [ ] Auto-create ticket on true_positive verdict with playbook `ticket` action
- [ ] Fields: summary, description (investigation report), priority, labels (MITRE techniques), custom fields
- [ ] Bi-directional sync: Jira status changes update ZOVARK response execution
- [ ] `POST /api/v1/integrations/jira/test` — Test connection
- [ ] Webhook receiver for Jira status change events
- [ ] Dashboard: Jira ticket link on investigation detail page
- [ ] Implement `ticket` action in `worker/response/actions.py`

## Technical Notes

- Jira Cloud REST API v3: `POST /rest/api/3/issue`
- Auth: email + API token (Basic auth)
- Store credentials encrypted in `tenants.settings`
BODY
)" \
    "backend,integration,priority:high" \
    "M4: Integrations"

create_issue \
    "Microsoft Teams integration — adaptive card notifications" \
    "$(cat <<'BODY'
## Description

Enterprise SOCs using Microsoft Teams need investigation notifications via Adaptive Cards.

## Acceptance Criteria

- [ ] Teams incoming webhook URL configuration per tenant
- [ ] Adaptive Card format: investigation summary with verdict badge, entity table, action buttons
- [ ] Notification types: investigation completed, approval requested, critical alert
- [ ] Action buttons: link to dashboard investigation page
- [ ] `POST /api/v1/integrations/teams/test` — Send test card
- [ ] Fallback: plain text if Adaptive Card fails

## Technical Notes

- Teams incoming webhooks accept POST with Adaptive Card JSON
- No bot framework needed — simple HTTP POST
BODY
)" \
    "backend,integration,priority:medium" \
    "M4: Integrations"

create_issue \
    "VirusTotal integration — automated IOC enrichment" \
    "$(cat <<'BODY'
## Description

ZOVARK extracts entities (IPs, domains, hashes) but doesn't check them against threat intelligence feeds. Integrate VirusTotal for auto-enrichment.

## Acceptance Criteria

- [ ] New activity: `enrich_ioc_virustotal` — check IP, domain, or hash against VT
- [ ] VT API v3: IP, domain, and file hash lookups
- [ ] Extract: detection ratio, reputation score, WHOIS data, community votes
- [ ] Store enrichment in `entities.enrichment_data` JSONB column (new column)
- [ ] Rate limiting: VT free tier = 4 req/min; Redis-based throttle
- [ ] Cache: Redis 24h TTL to avoid duplicate lookups
- [ ] Integration into `ExecuteTaskWorkflow` after entity extraction
- [ ] Dashboard: VT reputation badge on entities
- [ ] Configuration: `VIRUSTOTAL_API_KEY` (optional — skip if not set)

## Technical Notes

- VT API rate limits strict on free tier — token bucket in Redis
- Add `enrichment_data JSONB` column to entities table
BODY
)" \
    "backend,worker,integration,priority:high" \
    "M4: Integrations"

create_issue \
    "AbuseIPDB integration — IP reputation scoring" \
    "$(cat <<'BODY'
## Description

Complement VirusTotal with AbuseIPDB for IP-specific threat intelligence: abuse confidence scores, country data, report history.

## Acceptance Criteria

- [ ] New activity: `enrich_ip_abuseipdb`
- [ ] API v2: check IP with 90-day lookback
- [ ] Extract: abuse confidence score, total reports, country, ISP, usage type
- [ ] Store in `entities.enrichment_data` JSONB alongside VT data
- [ ] Rate limiting: free tier = 1000 checks/day
- [ ] Dashboard: abuse score badge (green <25, yellow 25-75, red >75)
- [ ] Configuration: `ABUSEIPDB_API_KEY` environment variable

## Technical Notes

- AbuseIPDB v2 API: `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90`
BODY
)" \
    "backend,worker,integration,priority:medium" \
    "M4: Integrations"

create_issue \
    "Email notifications — investigation digest and approval alerts" \
    "$(cat <<'BODY'
## Description

Critical findings and approval requests should be delivered via email with formatted investigation summaries.

## Acceptance Criteria

- [ ] SMTP configuration: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
- [ ] Email types: investigation completed, approval requested, daily digest
- [ ] HTML template: branded, investigation summary, entity table, action links
- [ ] Daily digest: summary of investigations, pending approvals (configurable time)
- [ ] User preferences: per-user notification settings
- [ ] Approval via email: signed magic link (24h expiry)
- [ ] Unsubscribe link in all emails
- [ ] `POST /api/v1/integrations/email/test` — Send test email

## Technical Notes

- Use Go `net/smtp` or `go-mail/mail`
- Signed approval URLs: HMAC-SHA256
BODY
)" \
    "backend,priority:medium" \
    "M4: Integrations"

create_issue \
    "ServiceNow ITSM integration — incident management" \
    "$(cat <<'BODY'
## Description

Enterprise customers use ServiceNow for incident management. Implement bi-directional integration.

## Acceptance Criteria

- [ ] ServiceNow configuration: instance URL, credentials
- [ ] Auto-create incident on true_positive verdict
- [ ] Field mapping: short_description, description, urgency, impact, assignment_group
- [ ] Bi-directional: ServiceNow state changes update ZOVARK
- [ ] Webhook receiver for ServiceNow events
- [ ] `POST /api/v1/integrations/servicenow/test` — Test connection
- [ ] Implement `ticket` action handler for ServiceNow variant

## Technical Notes

- ServiceNow REST API: `POST /api/now/table/incident`
BODY
)" \
    "backend,integration,priority:medium" \
    "M4: Integrations"

create_issue \
    "Webhook event catalog and developer documentation" \
    "$(cat <<'BODY'
## Description

ZOVARK supports outgoing webhooks but event types, payloads, and signatures are not documented.

## Acceptance Criteria

- [ ] Document all webhook event types with payload schemas
- [ ] Signature verification guide (HMAC-SHA256)
- [ ] Retry policy documentation
- [ ] `POST /api/v1/webhooks/test` — Send sample event to configured endpoint
- [ ] `POST /api/v1/webhooks/replay/:delivery_id` — Resend failed delivery
- [ ] Dashboard: webhook delivery log with status, response code, retry count
- [ ] Example code: Python, Node.js, Go webhook receivers

## Technical Notes

- Event types: investigation.completed, alert.received, approval.requested, response.executed, self_healing.event
BODY
)" \
    "backend,documentation,priority:medium" \
    "M4: Integrations"

# ============================================================
# M5: Intelligence & RAG
# ============================================================

create_issue \
    "pgvector index optimization — HNSW indexes for entity search" \
    "$(cat <<'BODY'
## Description

Entity similarity search uses `<->` operator on 768-dim vectors without any index. With 1M+ entities, queries do full table scans. Add HNSW indexes for sub-millisecond search.

## Acceptance Criteria

- [ ] HNSW index on `entities.embedding` (m=16, ef_construction=200)
- [ ] HNSW index on `entity_edges.embedding`
- [ ] HNSW index on `agent_skills.embedding`
- [ ] HNSW index on `investigation_memory.embedding`
- [ ] Tune `ef_search` parameter (default 100)
- [ ] Benchmark: search latency before/after (target: <10ms for top-10)
- [ ] Migration: `migrations/020_vector_indexes.sql`
- [ ] Set `hnsw.ef_search = 100` in connection setup
- [ ] Prometheus metric for vector search latency
- [ ] Document index maintenance (REINDEX, VACUUM)

## Technical Notes

- HNSW preferred over IVFFlat: better recall, no training, handles inserts
- pgvector 0.7+ required — verify Docker image
- Index creation on 1M rows: ~5 minutes
BODY
)" \
    "backend,performance,priority:critical" \
    "M5: Intelligence & RAG"

create_issue \
    "Semantic investigation search — RAG across past investigations" \
    "$(cat <<'BODY'
## Description

ZOVARK stores investigation memory with embeddings but doesn't expose semantic search to analysts. Add natural language search across past investigations.

## Acceptance Criteria

- [ ] `GET /api/v1/investigations/search?q=<natural language>` — semantic search
- [ ] Embed query using TEI (same model as entity embeddings)
- [ ] Search `investigation_memory.embedding` + `entities.embedding`
- [ ] Return: matching investigations with similarity score, verdict, key findings
- [ ] Hybrid search: vector similarity + keyword matching (BM25 via `pg_trgm`)
- [ ] Filters: date range, verdict type, severity, MITRE technique
- [ ] Dashboard: search bar on main page, results as investigation cards
- [ ] "Similar investigations" panel on task detail page
- [ ] Top 20 results, similarity threshold > 0.7

## Technical Notes

- Two-stage retrieval: vector search (top 100) → rerank by BM25 (top 20)
- TEI endpoint: `POST /embed`
BODY
)" \
    "backend,frontend,priority:high" \
    "M5: Intelligence & RAG"

create_issue \
    "Batch entity embedding pipeline" \
    "$(cat <<'BODY'
## Description

Entities are embedded one-at-a-time via individual TEI API calls. Implement batch embedding for bulk operations.

## Acceptance Criteria

- [ ] Batch function: `embed_batch(texts: list) -> list[list[float]]`
- [ ] Use TEI batch endpoint with array inputs
- [ ] Batch size: 32 texts per request (configurable)
- [ ] Retry logic: exponential backoff on TEI overload
- [ ] Use in: `write_entity_graph`, `bootstrap.process_entity`, `embed_investigation`
- [ ] Metrics: `zovark_embedding_batch_size`, `zovark_embedding_latency_seconds`
- [ ] Fallback: single-item embedding if batch fails

## Technical Notes

- TEI supports batch natively — pass array of inputs
- Current model: nomic-embed-text-v1.5 (768-dim, 8192 token context)
BODY
)" \
    "backend,worker,priority:medium" \
    "M5: Intelligence & RAG"

create_issue \
    "Fine-tuning evaluation metrics — BLEU, accuracy, regression testing" \
    "$(cat <<'BODY'
## Description

Fine-tuning pipeline exports training data but model evaluation is a stub. Add proper metrics to compare fine-tuned models against baseline.

## Acceptance Criteria

- [ ] Metrics: token accuracy, BLEU score, verdict accuracy, code validity rate
- [ ] Holdout test set: 20% reserved for evaluation
- [ ] Baseline comparison: fine-tuned vs production on same test set
- [ ] Regression gate: fine-tuned must score >= baseline to be promoted
- [ ] Evaluation report: JSON with per-metric scores, improvement examples
- [ ] Store in `model_registry.eval_score` (JSONB breakdown)
- [ ] A/B test integration: auto-create test between baseline and fine-tuned
- [ ] Dashboard: model performance comparison chart (admin)

## Technical Notes

- BLEU: `nltk.translate.bleu_score` or manual 4-gram
- Code validity: `compile(code, 'test.py', 'exec')`
- Verdict accuracy against labeled ground truth
BODY
)" \
    "backend,worker,priority:high" \
    "M5: Intelligence & RAG"

create_issue \
    "Embedding versioning and re-embedding pipeline" \
    "$(cat <<'BODY'
## Description

When embedding model changes, existing embeddings become incompatible. Track model version and support bulk re-embedding.

## Acceptance Criteria

- [ ] Add `embedding_model` column to tables with embeddings
- [ ] Set model identifier on every embed operation
- [ ] `ReembedWorkflow` — process all entities/memories with new model
- [ ] Batch processing: 1000 records per batch, progress tracking
- [ ] Version check: warn if query model differs from stored
- [ ] Migration: `migrations/021_embedding_versioning.sql`
- [ ] Admin endpoint: `POST /api/v1/admin/reembed`
BODY
)" \
    "backend,worker,priority:medium" \
    "M5: Intelligence & RAG"

create_issue \
    "Threat intelligence feed ingestion — STIX/TAXII" \
    "$(cat <<'BODY'
## Description

ZOVARK compares entities against own history but not external threat intel. Ingest STIX 2.1 indicators from TAXII feeds.

## Acceptance Criteria

- [ ] TAXII 2.1 client: poll configured feeds on schedule (hourly)
- [ ] Parse STIX 2.1: indicators (IP, domain, hash), attack patterns, campaigns
- [ ] New `threat_intel_indicators` table: type, value, source, confidence, validity
- [ ] Integrate into entity enrichment: check entities against TI indicators
- [ ] Dashboard: threat intel match badge on entities
- [ ] Feed management: add/remove TAXII feeds via API
- [ ] Stats: indicator counts by source, type, freshness
- [ ] Deduplication: same IOC from multiple feeds stored once

## Technical Notes

- Free feeds: MITRE ATT&CK TAXII, AlienVault OTX, CIRCL
- STIX parsing: `stix2` Python library in worker
BODY
)" \
    "backend,worker,integration,priority:medium" \
    "M5: Intelligence & RAG"

create_issue \
    "Investigation cache optimization — Redis + semantic dedup" \
    "$(cat <<'BODY'
## Description

Investigation cache uses SHA-256 exact match with 24h TTL. Add semantic deduplication for similar alerts.

## Acceptance Criteria

- [ ] Semantic cache: embed incoming alert, search for similar cached (threshold 0.95)
- [ ] If cache hit: return cached verdict without running workflow
- [ ] Cache levels: L1 (Redis, exact, 1h), L2 (pgvector, semantic, 24h)
- [ ] Cache stats: hit rate, miss rate, average savings per hit
- [ ] Cache invalidation endpoint: `POST /api/v1/cache/invalidate`
- [ ] Prometheus metrics: `zovark_cache_hits_total`, `zovark_cache_misses_total`
- [ ] Dashboard: cache performance panel
- [ ] Bypass flag: `force_reinvestigate=true` to skip cache

## Technical Notes

- Two-level cache: Redis for speed, pgvector for semantic
BODY
)" \
    "backend,worker,priority:medium" \
    "M5: Intelligence & RAG"

# ============================================================
# M6: Testing & Quality
# ============================================================

create_issue \
    "End-to-end test suite with docker-compose" \
    "$(cat <<'BODY'
## Description

No E2E tests verify the complete flow: API receives alert → Temporal schedules workflow → worker generates code → sandbox executes → results returned.

## Acceptance Criteria

- [ ] Python E2E framework running against live docker-compose stack
- [ ] Test cases:
  - Submit task → verify status transitions (pending → running → completed)
  - SIEM webhook alert → auto-investigation triggered
  - File upload → task created with file content
  - Approval flow: high-risk → approval created → approve → completion
  - Playbook resolution: matching alert → correct playbook selected
  - Entity extraction: entities written to graph
  - Memory enrichment: duplicate alert → enrichment from prior investigation
- [ ] CI integration: run on PR merge to master
- [ ] Timeout: 5 minutes max
- [ ] JUnit XML output for CI visualization

## Technical Notes

- Python `requests` + `pytest`
- Dedicated tenant `e2e-test` with known credentials
- Directory: `tests/e2e/`
BODY
)" \
    "testing,priority:high" \
    "M6: Testing & Quality"

create_issue \
    "Mock LLM server for offline testing" \
    "$(cat <<'BODY'
## Description

All tests require running vLLM (GPU). This blocks CI on CPU-only runners. Create a mock LLM server with canned responses.

## Acceptance Criteria

- [ ] Mock server: OpenAI-compatible `/v1/chat/completions` and `/v1/embeddings`
- [ ] Response modes: deterministic (same prompt → same response), random
- [ ] Canned responses for each prompt template (code gen, entity extraction, diagnosis)
- [ ] Realistic `usage` object (token counts)
- [ ] Configurable latency simulation (default 100ms)
- [ ] Configurable error rate for testing retry logic
- [ ] Docker service: `zovark-mock-llm` with `--profile test`
- [ ] CI: use mock LLM in GitHub Actions
- [ ] `ZOVARK_LLM_MOCK=true` environment variable

## Technical Notes

- OpenAI API format compatibility
- `scripts/record-llm-responses.py` to save real vLLM outputs as fixtures
- Directory: `tests/mock_llm/`
BODY
)" \
    "testing,priority:high" \
    "M6: Testing & Quality"

create_issue \
    "Sandbox escape test suite" \
    "$(cat <<'BODY'
## Description

ZOVARK's sandbox has 4 security layers but no automated tests verify they block malicious code. Build a comprehensive escape attempt suite.

## Acceptance Criteria

- [ ] Test categories:
  - Import bypass: `__import__`, `importlib`, encoding tricks
  - Network access: `socket`, `urllib`, `http.client`, DNS
  - File system escape: read `/etc/passwd`, write outside `/tmp`, symlinks
  - Process execution: `subprocess`, `os.system`, `ctypes.CDLL`
  - Resource exhaustion: fork bomb, memory allocation, CPU spin
  - Information disclosure: env vars, container metadata
- [ ] Each test verifies blocked (by AST prefilter or sandbox)
- [ ] Identify which layer blocks each attempt
- [ ] Regression test: run on every CI build
- [ ] Report: attack → blocked/allowed → which layer
- [ ] At least 30 distinct escape attempts

## Technical Notes

- Run against live stack (sandbox container required)
- Directory: `tests/security/`
BODY
)" \
    "testing,security,priority:high" \
    "M6: Testing & Quality"

create_issue \
    "Code coverage tracking with pytest-cov" \
    "$(cat <<'BODY'
## Description

No code coverage measurement exists. Add pytest-cov to the Python worker with CI enforcement.

## Acceptance Criteria

- [ ] Add `pytest-cov` to worker requirements
- [ ] Coverage configuration in `pyproject.toml`
- [ ] CI: generate coverage report on every PR
- [ ] Minimum threshold: 40% initially (increase over time)
- [ ] HTML report uploaded as CI artifact
- [ ] Badge: coverage percentage in README
- [ ] Exclude: test files, migrations, __init__.py
- [ ] Branch coverage tracking
BODY
)" \
    "testing,priority:medium" \
    "M6: Testing & Quality"

create_issue \
    "Load test automation in CI — performance regression gate" \
    "$(cat <<'BODY'
## Description

Load tests run manually. Automate in CI to catch performance regressions. Baseline: 17 invocations/min.

## Acceptance Criteria

- [ ] CI job: run load test on master merges
- [ ] Metrics: throughput (inv/min), p50/p95/p99 latency, error rate
- [ ] Regression gate: fail if throughput drops >20% or error rate >5%
- [ ] Baseline stored in `tests/benchmarks/baseline.json`
- [ ] Results published as CI artifact
- [ ] Comparison: current vs baseline in PR comment
- [ ] Environment: docker-compose with mock LLM for consistency

## Technical Notes

- Use existing `scripts/load_testing/run_load_test.py`
- Mock LLM (issue #40) required for deterministic benchmarks
BODY
)" \
    "testing,performance,priority:medium" \
    "M6: Testing & Quality"

create_issue \
    "Accuracy validation in CI — 50-alert corpus gate" \
    "$(cat <<'BODY'
## Description

50 labeled alerts exist in `worker/tests/accuracy/` but validation doesn't gate CI. Wire accuracy testing to catch LLM regression.

## Acceptance Criteria

- [ ] Run accuracy validation on master merges
- [ ] Metrics: verdict accuracy, false positive rate, false negative rate, avg confidence
- [ ] Gate: fail if accuracy < 70%
- [ ] Per-category breakdown by alert type
- [ ] Confusion matrix: TP, FP, TN, FN
- [ ] Dashboard: accuracy trend chart (admin)
- [ ] Expand corpus: 10 new labeled alerts per sprint
BODY
)" \
    "testing,priority:high" \
    "M6: Testing & Quality"

# ============================================================
# M7: Deployment & Scale
# ============================================================

create_issue \
    "Container registry — automated Docker image builds" \
    "$(cat <<'BODY'
## Description

CI builds Docker images but doesn't push to a registry. Deployments require building from source.

## Acceptance Criteria

- [ ] Push to `ghcr.io/7inaydas-cmyk/zovark-mvp/{service}:{tag}`
- [ ] Services: `api`, `worker`, `dashboard`, `mock-llm`
- [ ] Tags: `latest` (master), `v{semver}` (tags), `sha-{commit}` (every build)
- [ ] Multi-platform: `linux/amd64`
- [ ] CI: push on master merge and tag creation
- [ ] Image scanning: `trivy` before push (fail on critical CVEs)
- [ ] Size optimization: multi-stage builds, .dockerignore
- [ ] Update docker-compose to reference registry images

## Technical Notes

- GitHub Actions: `docker/build-push-action@v5`
- Worker image largest (~2GB) — optimize layers
BODY
)" \
    "deployment,priority:high" \
    "M7: Deployment & Scale"

create_issue \
    "Helm chart for Kubernetes deployment" \
    "$(cat <<'BODY'
## Description

K8s uses Kustomize. Helm is the standard package manager and provides better templating and release management.

## Acceptance Criteria

- [ ] Chart directory: `helm/zovark/`
- [ ] `values.yaml` with sane defaults
- [ ] Templates: Deployments, StatefulSets, Services, Ingress, HPA, NetworkPolicy, PVC
- [ ] Sub-charts: PostgreSQL (bitnami), Redis (bitnami) as optional dependencies
- [ ] Values files: dev, prod, airgap
- [ ] Chart tests: `helm test zovark` runs health checks
- [ ] Documentation: parameter table in README
- [ ] Publish to OCI registry

## Technical Notes

- Convert existing Kustomize manifests to Helm templates
BODY
)" \
    "deployment,priority:medium" \
    "M7: Deployment & Scale"

create_issue \
    "Blue-green deployment automation" \
    "$(cat <<'BODY'
## Description

Updates require downtime. Implement blue-green deployment for zero-downtime updates.

## Acceptance Criteria

- [ ] `scripts/deploy-blue-green.sh` — orchestrate blue-green switch
- [ ] Deploy new version alongside current
- [ ] Health check before switching traffic
- [ ] Reverse proxy switches upstream
- [ ] Workers: graceful drain (finish current workflows, stop accepting new)
- [ ] Rollback: one-command switch back
- [ ] Database migrations: run before switch (backward-compatible only)
- [ ] K8s: `RollingUpdate` with `maxSurge: 1, maxUnavailable: 0`
BODY
)" \
    "deployment,priority:medium" \
    "M7: Deployment & Scale"

create_issue \
    "Multi-region deployment architecture" \
    "$(cat <<'BODY'
## Description

ZOVARK assumes single-region. Design multi-region for global SOC teams with data residency controls.

## Acceptance Criteria

- [ ] Architecture document: multi-region topology
- [ ] Data residency: tenant data in configured region (EU, US, APAC)
- [ ] Database: PostgreSQL logical replication
- [ ] API: global load balancer routing
- [ ] Temporal: per-region clusters with cross-region routing
- [ ] Tenant config: `data_region` field
- [ ] Document trade-offs: consistency vs latency
BODY
)" \
    "deployment,architecture,priority:low" \
    "M7: Deployment & Scale"

create_issue \
    "Disaster recovery runbook and automated failover" \
    "$(cat <<'BODY'
## Description

No DR plan exists. Create a runbook and automate critical recovery steps.

## Acceptance Criteria

- [ ] DR runbook: `docs/DISASTER_RECOVERY.md`
- [ ] Scenarios: server crash, DB corruption, network partition, GPU failure
- [ ] RPO: 1 hour (hourly backups)
- [ ] RTO: 30 minutes (automated restore)
- [ ] `scripts/disaster-recovery.sh` — automated restore from MinIO backup
- [ ] GPU failure: automatic Ollama/CPU fallback (air-gap mode)
- [ ] Communication template for incident updates
- [ ] DR drill: quarterly test procedure

## Technical Notes

- Depends on backup automation (issue #6)
BODY
)" \
    "deployment,documentation,priority:high" \
    "M7: Deployment & Scale"

create_issue \
    "Infrastructure as Code — Terraform modules" \
    "$(cat <<'BODY'
## Description

Cloud deployments are manual. Create Terraform modules for AWS that provision the complete ZOVARK stack.

## Acceptance Criteria

- [ ] Module: `terraform/aws/`
- [ ] Resources: VPC, subnets, security groups, EKS, RDS PostgreSQL, ElastiCache, S3, ECR, ALB, Route53
- [ ] GPU support: `g4dn.xlarge` for vLLM inference
- [ ] Variables: region, instance types, domain, CIDR ranges
- [ ] Outputs: API URL, dashboard URL, monitoring URLs
- [ ] State: S3 backend with DynamoDB locking
- [ ] Cost estimate in `terraform plan`
- [ ] Clean destroy: `terraform destroy` removes all resources
BODY
)" \
    "deployment,priority:low" \
    "M7: Deployment & Scale"

# ============================================================
# M8: Workflow Automation
# ============================================================

create_issue \
    "Auto-trigger response playbooks on investigation completion" \
    "$(cat <<'BODY'
## Description

`ResponsePlaybookWorkflow` exists but is never auto-triggered. When an investigation completes with `verdict=true_positive`, matching playbooks should execute automatically.

## Acceptance Criteria

- [ ] After `ExecuteTaskWorkflow` completes with true_positive:
  - Query `response_playbooks` for matching trigger conditions
  - Auto-start `ResponsePlaybookWorkflow` with investigation context
- [ ] Trigger matching: playbook conditions match alert metadata
- [ ] Priority ordering: highest-priority playbook first
- [ ] Dry-run mode: tenant setting to log without executing
- [ ] Dedup: skip if already triggered for this investigation + playbook
- [ ] Audit log: `response_auto_triggered` event type
- [ ] Dashboard: show triggered response actions on investigation detail
- [ ] Per-tenant enable/disable in settings

## Technical Notes

- Add continuation in `ExecuteTaskWorkflow.run()` after final verdict
- `find_matching_playbooks` activity already exists
BODY
)" \
    "backend,worker,priority:high" \
    "M8: Workflow Automation"

create_issue \
    "Scheduled workflow execution — cron-based detection and SRE" \
    "$(cat <<'BODY'
## Description

Detection and SRE workflows exist but must be triggered manually. Add Temporal schedules for recurring execution.

## Acceptance Criteria

- [ ] `DetectionGenerationWorkflow`: daily at 03:00 UTC
- [ ] `SelfHealingWorkflow`: every 30 minutes (dry-run mode)
- [ ] `CrossTenantRefreshWorkflow`: hourly materialized view refresh
- [ ] Schedule management API: create, update, delete, list, pause, resume
- [ ] Schedule config in `tenants.settings` JSONB
- [ ] Dashboard: schedule management page (admin)

## Technical Notes

- Use Temporal Schedules API (`client.create_schedule`)
- Default schedules created on worker startup
BODY
)" \
    "backend,worker,priority:high" \
    "M8: Workflow Automation"

create_issue \
    "Alert correlation engine — group related alerts into incidents" \
    "$(cat <<'BODY'
## Description

Each SIEM alert creates a separate investigation. Related alerts should be correlated into incidents for holistic investigation.

## Acceptance Criteria

- [ ] Correlation rules: same source_ip (15min), same MITRE technique (1h), same entity cluster
- [ ] New `incidents` table: id, tenant_id, title, severity, status, alert_ids, investigation_ids
- [ ] On new alert: check for matching open incidents
- [ ] If match: add alert to existing incident, enrich investigation context
- [ ] If no match: create new incident with single alert
- [ ] Incident escalation: alert count exceeds threshold → upgrade severity
- [ ] Dashboard: incident list page, incident detail with correlated alerts
- [ ] API: `GET /api/v1/incidents`, `GET /api/v1/incidents/:id`, `POST /api/v1/incidents/:id/merge`
- [ ] Correlated alerts provide additional context to LLM prompt

## Technical Notes

- Entity-based correlation via `entities` table and edges
- Configurable correlation window per tenant
BODY
)" \
    "backend,worker,priority:high" \
    "M8: Workflow Automation"

create_issue \
    "Investigation SLA monitoring and escalation" \
    "$(cat <<'BODY'
## Description

No SLA tracking for investigation completion times. Add configurable SLAs with automatic escalation.

## Acceptance Criteria

- [ ] SLA configuration per tenant: `{"sla": {"critical": "15m", "high": "1h", "medium": "4h", "low": "24h"}}`
- [ ] Monitor `agent_tasks` for SLA breaches
- [ ] Escalation: notification, priority boost, reassignment
- [ ] SLA status: `within_sla`, `warning` (80% elapsed), `breached`
- [ ] Dashboard: SLA compliance widget
- [ ] API: `GET /api/v1/sla/compliance`
- [ ] Prometheus: `zovark_sla_breached_total{severity}`
- [ ] Scheduled check every 5 minutes

## Technical Notes

- Temporal schedule for SLA monitoring activity
BODY
)" \
    "backend,priority:medium" \
    "M8: Workflow Automation"

create_issue \
    "Auto-retrain trigger — accuracy-driven model update" \
    "$(cat <<'BODY'
## Description

Fine-tuning pipeline never auto-triggers. When accuracy drops below threshold, automatically trigger retraining.

## Acceptance Criteria

- [ ] Weekly accuracy check from `investigation_feedback` table
- [ ] Trigger: accuracy < 75% over last 100 investigations
- [ ] Guard: max 1 fine-tuning run per week
- [ ] Pipeline: export → quality score → evaluate → compare → promote
- [ ] Notification: alert admin with accuracy metrics
- [ ] Rollback: auto-revert if fine-tuned model performs worse
- [ ] Dashboard: model accuracy trend, retrain history

## Technical Notes

- Temporal schedule for weekly accuracy check
- Depends on fine-tuning evaluation metrics (issue #35)
BODY
)" \
    "backend,worker,priority:medium" \
    "M8: Workflow Automation"

echo ""
echo "=== Done! ==="
echo "All issues created successfully."
