#!/bin/bash
# Bulk create HYDRA GitHub issues
GH="/c/Program Files/GitHub CLI/gh.exe"
REPO="7inaydas-cmyk/hydra-mvp"
CREATED=0

ci() {
    local title="$1" milestone="$2" labels="$3" body="$4"
    echo "$body" > /tmp/hydra_issue.md
    url=$("$GH" issue create --repo "$REPO" --title "$title" --milestone "$milestone" --label "$labels" --body-file /tmp/hydra_issue.md 2>&1)
    CREATED=$((CREATED + 1))
    echo "  #$CREATED: $title -> $url"
    sleep 1
}

echo "=== M1: Production Foundation ==="

ci "TLS termination — HTTPS enforcement for all services" "M1: Production Foundation" "security,deployment,priority:critical" \
"## Description
All HYDRA services communicate over plaintext HTTP. Production must encrypt browser-API, API-LiteLLM, and API-Temporal traffic.

## Acceptance Criteria
- [ ] Add Caddy or Traefik reverse proxy to \`docker-compose.yml\`
- [ ] Auto-generate self-signed certs for dev (mkcert)
- [ ] Let's Encrypt ACME for production domains
- [ ] API accessible only via HTTPS (443)
- [ ] Dashboard served behind reverse proxy
- [ ] Internal services remain HTTP on \`hydra-internal\` network
- [ ] \`HYDRA_TLS_ENABLED=true\` env variable to toggle
- [ ] HSTS header on all API responses when TLS enabled
- [ ] Document certificate setup in DEPLOYMENT_GUIDE.md

## Technical Notes
- Caddy is simplest (auto-TLS, zero-config); Traefik more flexible
- Internal network stays HTTP — TLS only at ingress
- K8s: use cert-manager + Ingress"

ci "Secrets management — Vault integration for credentials" "M1: Production Foundation" "security,backend,priority:high" \
"## Description
All secrets in \`.env\` files visible in \`docker inspect\`, process env, and logs. Production requires proper secrets manager.

## Acceptance Criteria
- [ ] Abstract secret loading: \`secrets.Get(key)\` in Go, \`get_secret(key)\` in Python
- [ ] 3 backends: environment variables (default), HashiCorp Vault, AWS Secrets Manager
- [ ] \`HYDRA_SECRETS_BACKEND=env|vault|aws\` env variable
- [ ] Vault: AppRole auth, KV v2 engine
- [ ] Rotate DB password without downtime (PgBouncer handles reconnection)
- [ ] JWT signing key rotation: multiple active keys (JWK set)
- [ ] Remove hardcoded secrets from \`docker-compose.yml\`
- [ ] Add \`scripts/rotate-secrets.sh\` helper"

ci "Two-factor authentication (TOTP)" "M1: Production Foundation" "security,backend,frontend,priority:high" \
"## Description
Admin/analyst accounts need 2FA. Add TOTP support compatible with Google Authenticator, Authy, 1Password.

## Acceptance Criteria
- [ ] Add \`totp_secret\` (encrypted) and \`totp_enabled\` columns to users table
- [ ] \`POST /api/v1/auth/2fa/setup\` — Generate TOTP secret, return QR code URI
- [ ] \`POST /api/v1/auth/2fa/verify\` — Verify TOTP code and enable 2FA
- [ ] \`POST /api/v1/auth/2fa/disable\` — Disable 2FA (requires current code)
- [ ] Login flow: require TOTP after password when enabled
- [ ] Generate 10 backup recovery codes (stored hashed)
- [ ] Rate-limit: 5 attempts per 5 minutes
- [ ] Dashboard: 2FA setup page with QR code
- [ ] Admin enforcement option per tenant

## Technical Notes
- Go: \`pquerna/otp\` library, 30s window, 6 digits, SHA1
- Encrypt \`totp_secret\` with AES-256-GCM"

ci "API key authentication for machine-to-machine access" "M1: Production Foundation" "security,backend,priority:high" \
"## Description
External systems need API access without user JWT tokens. Add API key support with permissions, rate limits, and audit logging.

## Acceptance Criteria
- [ ] New \`api_keys\` table with key_hash, prefix, permissions JSONB, rate_limit, expires_at
- [ ] \`POST /api/v1/api-keys\` — Create (returns full key once, stores hash only)
- [ ] \`GET /api/v1/api-keys\` — List (prefix only)
- [ ] \`DELETE /api/v1/api-keys/:id\` — Revoke
- [ ] Accept \`X-API-Key\` header on all endpoints
- [ ] Per-key permissions: \`tasks:read\`, \`tasks:write\`, \`alerts:write\`, \`admin:*\`
- [ ] Per-key rate limit override (default: 300 req/min)
- [ ] Key format: \`hydra_sk_\` + 32 random bytes (base62)
- [ ] Keys scoped to single tenant"

ci "Database backup automation with S3/MinIO snapshots" "M1: Production Foundation" "deployment,backend,priority:high" \
"## Description
PostgreSQL on Docker volumes with no backup. Disk failure loses everything.

## Acceptance Criteria
- [ ] New \`hydra-backup\` service (Alpine + pg_dump + mc)
- [ ] Daily full backup at 02:00 UTC, hourly WAL archiving
- [ ] Store in MinIO \`hydra-backups/\` with date-prefixed paths
- [ ] Retention: 7 daily, 4 weekly, 3 monthly
- [ ] \`scripts/backup.sh\` and \`scripts/restore.sh\`
- [ ] AES-256 encryption
- [ ] Verification: restore to temp DB, check table counts
- [ ] Prometheus metric: \`hydra_backup_last_success_timestamp\`"

ci "Audit log export and SIEM forwarding" "M1: Production Foundation" "security,backend,priority:medium" \
"## Description
Audit events in PostgreSQL only. Compliance requires forwarding to external SIEM and archival to object storage.

## Acceptance Criteria
- [ ] \`GET /api/v1/audit/export\` — JSONL download (date range, max 10k)
- [ ] Syslog forwarding: \`HYDRA_SYSLOG_TARGET=tcp://splunk:514\`
- [ ] CEF format for SIEM compatibility
- [ ] S3/MinIO archival: daily export of events >30 days old
- [ ] Tamper detection: HMAC chain on exported logs
- [ ] Dashboard: audit log viewer with search and filters"

echo ""
echo "=== M2: API & SDK ==="

ci "OpenAPI 3.1 specification with Swagger UI" "M2: API & SDK" "backend,priority:high" \
"## Description
44+ endpoints documented only in markdown. No interactive API explorer. Generate OpenAPI spec and serve Swagger UI.

## Acceptance Criteria
- [ ] Generate \`openapi.yaml\` (use \`swaggo/swag\` or hand-write)
- [ ] Serve Swagger UI at \`/api/docs\`
- [ ] Document all 44+ endpoints with schemas
- [ ] Auth schemes: Bearer JWT and API Key
- [ ] Example values for all fields
- [ ] Error response schemas
- [ ] Validate spec in CI
- [ ] Version header: \`X-API-Version: 1.0.0\`"

ci "Consistent API response envelope and error format" "M2: API & SDK" "backend,priority:high" \
"## Description
Inconsistent response formats across handlers. Standardize into predictable envelope.

## Acceptance Criteria
- [ ] Success: \`{data, meta: {request_id, timestamp}}\`
- [ ] Lists: \`{data: [], meta: {total, page, per_page}}\`
- [ ] Errors: \`{error: {code, message, details}}\`
- [ ] \`X-Request-Id\` header on all responses
- [ ] Propagate request ID through Temporal for tracing
- [ ] Gzip compression middleware
- [ ] Error codes enum: AUTH_FAILED, VALIDATION_FAILED, NOT_FOUND, RATE_LIMITED
- [ ] Update all handlers to use envelope helpers
- [ ] Update dashboard to parse new format"

ci "Python SDK — typed client library for HYDRA API" "M2: API & SDK" "sdk,priority:high" \
"## Description
Every integration hand-crafts HTTP calls. Python SDK reduces integration time from hours to minutes.

## Acceptance Criteria
- [ ] Package: \`hydra-sdk\` (PyPI-publishable)
- [ ] \`HydraClient(base_url, api_key=None, jwt_token=None)\`
- [ ] Methods: \`client.tasks.list()\`, \`client.tasks.create()\`, etc.
- [ ] Response dataclasses: Task, Investigation, Alert, Entity, Playbook
- [ ] \`AsyncHydraClient\` using \`httpx.AsyncClient\`
- [ ] Auto-pagination helpers
- [ ] Error classes: HydraAPIError, HydraAuthError, HydraRateLimitError
- [ ] Retry with exponential backoff on 429/503
- [ ] Minimal deps: \`httpx\`, \`dataclasses\`
- [ ] Directory: \`sdk/python/\`"

ci "Per-tenant API rate limiting with Redis" "M2: API & SDK" "backend,priority:high" \
"## Description
Only auth endpoints rate-limited. Task submission unlimited. Single tenant can DOS the system.

## Acceptance Criteria
- [ ] Redis sliding window counter middleware in Go
- [ ] Tiers: free (30/min), professional (120/min), enterprise (600/min)
- [ ] Separate limits for: general API, task creation, webhooks, bulk
- [ ] Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
- [ ] 429 with Retry-After when exceeded
- [ ] Per-tenant override in \`tenants.settings\` JSONB
- [ ] Admin exempt
- [ ] Burst allowance: 2x for 10s window
- [ ] Prometheus: \`hydra_api_rate_limited_total{tenant, endpoint}\`"

ci "Bulk task creation endpoint" "M2: API & SDK" "backend,priority:medium" \
"## Description
Tasks created one-at-a-time. SOC teams need batch creation for morning triage.

## Acceptance Criteria
- [ ] \`POST /api/v1/tasks/bulk\` — up to 100 task definitions
- [ ] Validate all before creating (atomic batch)
- [ ] Dedup: skip alerts matching existing fingerprints
- [ ] Response: \`{created: [...], skipped: [...], failed: [...]}\`
- [ ] Queue to Temporal in parallel
- [ ] Separate rate limit: 10 req/min
- [ ] Priority ordering: high-severity first"

ci "Investigation report export (PDF + JSON)" "M2: API & SDK" "backend,priority:medium" \
"## Description
Results viewable only in dashboard. Analysts need export for ticketing, briefings, compliance.

## Acceptance Criteria
- [ ] \`GET /api/v1/tasks/:id/report\` — Accept: application/json, application/pdf, text/markdown
- [ ] JSON: structured findings, entities, timeline, verdict
- [ ] Markdown: human-readable (worker already generates)
- [ ] PDF: branded, syntax-highlighted code blocks, TOC
- [ ] Cache generated reports in MinIO
- [ ] Dashboard: Download Report button (PDF + JSON)"

ci "Content negotiation — CSV and JSONL export for lists" "M2: API & SDK" "backend,priority:low" \
"## Description
JSON-only list endpoints. SOC teams need CSV for Excel and JSONL for log pipelines.

## Acceptance Criteria
- [ ] \`Accept: text/csv\` on list endpoints
- [ ] \`Accept: application/x-ndjson\` for JSONL streaming
- [ ] CSV with header row
- [ ] \`?format=csv\` query param alternative
- [ ] Content-Disposition filename header
- [ ] Date range filter for export scoping
- [ ] Max 50k records, streaming for larger sets"

echo ""
echo "=== M3: Dashboard Evolution ==="

ci "Admin panel — tenant management UI" "M3: Dashboard Evolution" "frontend,priority:high" \
"## Description
Tenant CRUD API-only. Admins must use curl to manage tenants, users, settings.

## Acceptance Criteria
- [ ] Admin section at \`/admin\` (role guarded)
- [ ] Sidebar: Tenants, Users, Models, System Health
- [ ] Tenant list: name, slug, tier, user count, task count
- [ ] Tenant detail: settings editor, usage stats, rate limits
- [ ] Create tenant form
- [ ] User management: list, change roles, lock/unlock
- [ ] System stats: total tasks, LLM usage, error rate
- [ ] Activity feed: recent audit events"

ci "Approval queue UI — visual pending approvals" "M3: Dashboard Evolution" "frontend,priority:high" \
"## Description
High-risk investigation steps require approval but managed via API only.

## Acceptance Criteria
- [ ] Approval queue page at \`/approvals\`
- [ ] Card-based layout: investigation context, generated code, risk assessment
- [ ] Syntax-highlighted code viewer with dangerous ops highlighted red
- [ ] Actions: Approve, Reject (with comment), Skip
- [ ] Real-time updates (polling, then SSE)
- [ ] Notification badge in sidebar
- [ ] Approval history with timestamps
- [ ] Mobile-responsive: swipe to approve/reject"

ci "LLM cost tracking dashboard" "M3: Dashboard Evolution" "frontend,priority:high" \
"## Description
LLM calls logged to \`llm_call_log\` with costs but invisible in dashboard.

## Acceptance Criteria
- [ ] Cost page at \`/costs\`
- [ ] Summary cards: total cost (24h/7d/30d), avg per investigation, total tokens
- [ ] Breakdown by model tier (bar chart)
- [ ] Breakdown by activity (pie chart)
- [ ] 30-day trend line chart
- [ ] Per-investigation cost on task detail page
- [ ] Budget alerts with configurable threshold
- [ ] Per-tenant cost view (admin)
- [ ] CSV export"

ci "Entity graph visualization" "M3: Dashboard Evolution" "frontend,priority:medium" \
"## Description
Entity relationships stored in DB but invisible to analysts. Visualize connections to reveal attack patterns.

## Acceptance Criteria
- [ ] Entity graph tab on investigation detail page
- [ ] Force-directed layout: entities as nodes, relationships as edges
- [ ] Color by type: IP=blue, domain=green, hash=orange, user=purple
- [ ] Node size proportional to connections
- [ ] Edge labels: communicates_with, resolved_to, etc.
- [ ] Click node: verdict, confidence, related investigations
- [ ] Cross-investigation shared entity view
- [ ] Zoom, pan, fullscreen
- [ ] Export as PNG/SVG"

ci "Real-time investigation updates via Server-Sent Events" "M3: Dashboard Evolution" "backend,frontend,priority:medium" \
"## Description
Investigation progress shown by polling. Implement SSE for real-time push.

## Acceptance Criteria
- [ ] \`GET /api/v1/events/stream\` — SSE endpoint
- [ ] Events: step_started, step_completed, investigation_completed, approval_requested, alert_received
- [ ] Filter by tenant from JWT
- [ ] Heartbeat every 30s
- [ ] Last-Event-ID for reconnection
- [ ] Dashboard: replace polling with SSE
- [ ] Fallback to polling if SSE fails

## Technical Notes
- Go: \`http.Flusher\` interface
- Redis pub/sub for cross-instance fan-out"

ci "Investigation timeline with MITRE ATT&CK mapping" "M3: Dashboard Evolution" "frontend,priority:medium" \
"## Description
Map investigation findings to MITRE ATT&CK techniques. Show attack progression through kill chain.

## Acceptance Criteria
- [ ] Timeline component on task detail page
- [ ] Steps mapped to MITRE tactic/technique
- [ ] Kill chain visualization: Recon to Impact
- [ ] Click technique: MITRE link + evidence
- [ ] Coverage heat map: detection gaps
- [ ] STIX 2.1 export of findings

## Technical Notes
- 691 techniques already in \`mitre_techniques\` table"

ci "Dark mode / light mode toggle" "M3: Dashboard Evolution" "frontend,priority:low" \
"## Description
Dashboard is dark-theme only. Add toggle with system preference detection.

## Acceptance Criteria
- [ ] Toggle button in header (sun/moon icon)
- [ ] Respect \`prefers-color-scheme\` media query
- [ ] Persist in localStorage
- [ ] Tailwind dark mode class strategy
- [ ] Smooth 150ms transition
- [ ] All components readable in both modes"

ci "Playbook builder UI — visual workflow editor" "M3: Dashboard Evolution" "frontend,priority:medium" \
"## Description
Response playbooks created via API with JSON. Analysts need visual drag-and-drop editor.

## Acceptance Criteria
- [ ] Builder at \`/playbooks/new\` and \`/playbooks/:id/edit\`
- [ ] Drag-and-drop canvas: notify, ticket, quarantine, isolate, remediate, rollback
- [ ] Click step to configure parameters
- [ ] Conditional branching: if verdict = true_positive
- [ ] Trigger configuration: alert types, severities
- [ ] Preview mode: dry-run visualization
- [ ] Template library: phishing, ransomware, C2

## Technical Notes
- Use \`reactflow\` library for node-based editor"

ci "SIEM alerts management UI with advanced filtering" "M3: Dashboard Evolution" "frontend,priority:high" \
"## Description
SIEM alerts page shows minimal data, no filtering. Analysts need efficient triage.

## Acceptance Criteria
- [ ] Enhanced alerts page at \`/alerts\`
- [ ] Filters: severity, status, source, date range
- [ ] Full-text search across alert name, IPs
- [ ] Sort by severity, timestamp, status
- [ ] Bulk actions: investigate, dismiss as FP
- [ ] Alert detail slide-out: full JSON, MITRE mapping
- [ ] Auto-refresh for new alerts
- [ ] Stats bar: counts by severity
- [ ] One-click investigate from alert card"

echo ""
echo "=== M4: Integrations ==="

ci "Slack integration — notifications and interactive approvals" "M4: Integrations" "backend,integration,priority:high" \
"## Description
SOC teams live in Slack. Push investigation results, approval requests, and critical findings.

## Acceptance Criteria
- [ ] Config: \`HYDRA_SLACK_BOT_TOKEN\`, \`HYDRA_SLACK_SIGNING_SECRET\`
- [ ] Notifications: investigation completed, approval requested, critical finding
- [ ] Channel routing configurable per tenant
- [ ] Rich message cards: verdict, entities, dashboard link
- [ ] Interactive Approve/Reject buttons
- [ ] \`/hydra investigate <alert>\` slash command
- [ ] \`/hydra status\` slash command
- [ ] Thread replies for follow-up steps

## Technical Notes
- Use \`slack-go/slack\` library
- Channel mapping in \`tenants.settings\` JSONB"

ci "Jira integration — automatic ticket creation from verdicts" "M4: Integrations" "backend,integration,priority:high" \
"## Description
SOAR playbook \`ticket\` action is a stub (NotImplementedError). Implement Jira Cloud integration.

## Acceptance Criteria
- [ ] Jira config per tenant: URL, email, API token, project key
- [ ] Auto-create ticket on true_positive verdict
- [ ] Fields: summary, description (report), priority, labels (MITRE), custom fields
- [ ] Bi-directional: Jira status changes update HYDRA
- [ ] \`POST /api/v1/integrations/jira/test\` — Test connection
- [ ] Dashboard: Jira ticket link on investigation detail
- [ ] Implement \`ticket\` action in \`worker/response/actions.py\`

## Technical Notes
- Jira Cloud REST API v3
- Auth: email + API token (Basic auth)"

ci "Microsoft Teams integration — adaptive card notifications" "M4: Integrations" "backend,integration,priority:medium" \
"## Description
Enterprise SOCs on Teams need investigation notifications via Adaptive Cards.

## Acceptance Criteria
- [ ] Teams incoming webhook URL per tenant
- [ ] Adaptive Card: investigation summary, verdict badge, entity table
- [ ] Notification types: completed, approval requested, critical alert
- [ ] Action buttons: link to dashboard
- [ ] \`POST /api/v1/integrations/teams/test\` — Send test card
- [ ] Fallback: plain text if Adaptive Card fails"

ci "VirusTotal integration — automated IOC enrichment" "M4: Integrations" "backend,worker,integration,priority:high" \
"## Description
HYDRA extracts entities but doesn't check threat intelligence feeds. Integrate VirusTotal for auto-enrichment.

## Acceptance Criteria
- [ ] New activity: \`enrich_ioc_virustotal\`
- [ ] VT API v3: IP, domain, file hash lookups
- [ ] Extract: detection ratio, reputation, WHOIS, community votes
- [ ] Store in \`entities.enrichment_data\` JSONB (new column)
- [ ] Rate limiting: 4 req/min (free tier), Redis throttle
- [ ] Cache: Redis 24h TTL
- [ ] Integrate into ExecuteTaskWorkflow after entity extraction
- [ ] Dashboard: VT reputation badge on entities
- [ ] Config: \`VIRUSTOTAL_API_KEY\` (optional)"

ci "AbuseIPDB integration — IP reputation scoring" "M4: Integrations" "backend,worker,integration,priority:medium" \
"## Description
Complement VirusTotal with AbuseIPDB for IP-specific threat intelligence.

## Acceptance Criteria
- [ ] New activity: \`enrich_ip_abuseipdb\`
- [ ] API v2: check IP with 90-day lookback
- [ ] Extract: abuse confidence score, reports, country, ISP
- [ ] Store in \`entities.enrichment_data\` JSONB
- [ ] Rate limiting: 1000/day
- [ ] Dashboard: abuse score badge (green/yellow/red)
- [ ] Config: \`ABUSEIPDB_API_KEY\`"

ci "Email notifications — investigation digest and approval alerts" "M4: Integrations" "backend,priority:medium" \
"## Description
Critical findings should be delivered via email with formatted summaries.

## Acceptance Criteria
- [ ] SMTP config: host, port, user, password, from
- [ ] Types: investigation completed, approval requested, daily digest
- [ ] HTML template: branded, investigation summary, entity table
- [ ] Daily digest at configurable time
- [ ] Per-user notification preferences
- [ ] Approval via email: signed magic link (24h expiry)
- [ ] Unsubscribe link
- [ ] \`POST /api/v1/integrations/email/test\`"

ci "ServiceNow ITSM integration — incident management" "M4: Integrations" "backend,integration,priority:medium" \
"## Description
Enterprise customers use ServiceNow. Implement bi-directional incident integration.

## Acceptance Criteria
- [ ] Config: instance URL, credentials
- [ ] Auto-create incident on true_positive verdict
- [ ] Field mapping: short_description, urgency, impact, assignment_group
- [ ] Bi-directional: ServiceNow state changes update HYDRA
- [ ] Webhook receiver for ServiceNow events
- [ ] \`POST /api/v1/integrations/servicenow/test\`"

ci "Webhook event catalog and developer documentation" "M4: Integrations" "backend,priority:medium" \
"## Description
Outgoing webhooks exist but event types, payloads, and signatures are undocumented.

## Acceptance Criteria
- [ ] Document all event types with payload JSON schemas
- [ ] Signature verification guide (HMAC-SHA256)
- [ ] Retry policy documentation
- [ ] \`POST /api/v1/webhooks/test\` — Send sample event
- [ ] \`POST /api/v1/webhooks/replay/:delivery_id\` — Resend failed
- [ ] Dashboard: delivery log with status, response code
- [ ] Example receivers: Python, Node.js, Go"

echo ""
echo "=== M5: Intelligence & RAG ==="

ci "pgvector index optimization — HNSW indexes for entity search" "M5: Intelligence & RAG" "backend,performance,priority:critical" \
"## Description
Entity similarity search does full table scans on 768-dim vectors. 1M+ entities means seconds per query. Add HNSW indexes.

## Acceptance Criteria
- [ ] HNSW index on \`entities.embedding\` (m=16, ef_construction=200)
- [ ] HNSW index on \`entity_edges.embedding\`
- [ ] HNSW index on \`agent_skills.embedding\`
- [ ] HNSW index on \`investigation_memory.embedding\`
- [ ] Tune \`ef_search=100\`
- [ ] Benchmark: target <10ms for top-10 neighbors
- [ ] Migration: \`migrations/020_vector_indexes.sql\`
- [ ] Prometheus metric for vector search latency
- [ ] Document index maintenance"

ci "Semantic investigation search — RAG across past investigations" "M5: Intelligence & RAG" "backend,frontend,priority:high" \
"## Description
Investigation memory has embeddings but no semantic search exposed. Add natural language search across past cases.

## Acceptance Criteria
- [ ] \`GET /api/v1/investigations/search?q=<query>\`
- [ ] Embed query via TEI, search investigation_memory + entities
- [ ] Return: matching investigations, similarity score, verdict, findings
- [ ] Hybrid: vector + keyword matching (pg_trgm BM25)
- [ ] Filters: date, verdict, severity, MITRE technique
- [ ] Dashboard: search bar, results as investigation cards
- [ ] Similar investigations panel on task detail page
- [ ] Top 20 results, threshold > 0.7"

ci "Batch entity embedding pipeline" "M5: Intelligence & RAG" "backend,worker,priority:medium" \
"## Description
Entities embedded one-at-a-time via individual TEI calls. Slow for bulk operations.

## Acceptance Criteria
- [ ] \`embed_batch(texts)\` function using TEI batch endpoint
- [ ] Batch size: 32 per request (configurable)
- [ ] Retry with exponential backoff on TEI overload
- [ ] Use in: write_entity_graph, bootstrap, embed_investigation
- [ ] Metrics: batch_size, latency_seconds
- [ ] Fallback to single-item if batch fails"

ci "Fine-tuning evaluation metrics — BLEU, accuracy, regression testing" "M5: Intelligence & RAG" "backend,worker,priority:high" \
"## Description
Fine-tuning pipeline exports data but model evaluation is a stub. Add proper metrics.

## Acceptance Criteria
- [ ] Metrics: token accuracy, BLEU, verdict accuracy, code validity rate
- [ ] Holdout: 20% reserved for evaluation
- [ ] Baseline comparison on same test set
- [ ] Regression gate: fine-tuned >= baseline to promote
- [ ] Report: JSON with per-metric scores
- [ ] Store in \`model_registry.eval_score\` JSONB
- [ ] A/B test integration: auto-create baseline vs fine-tuned
- [ ] Dashboard: performance comparison chart"

ci "Embedding versioning and re-embedding pipeline" "M5: Intelligence & RAG" "backend,worker,priority:medium" \
"## Description
Model changes make existing embeddings incompatible. Track version and support bulk re-embedding.

## Acceptance Criteria
- [ ] Add \`embedding_model\` column to all vector tables
- [ ] Set model identifier on every embed
- [ ] \`ReembedWorkflow\` — batch process all records with new model
- [ ] 1000 records per batch, progress tracking
- [ ] Version check: warn if query model differs
- [ ] \`POST /api/v1/admin/reembed\` to trigger"

ci "Threat intelligence feed ingestion — STIX/TAXII" "M5: Intelligence & RAG" "backend,worker,integration,priority:medium" \
"## Description
Compare entities against external threat intel, not just own history. Ingest STIX 2.1 indicators.

## Acceptance Criteria
- [ ] TAXII 2.1 client: poll feeds hourly
- [ ] Parse STIX 2.1: indicators, attack patterns, campaigns
- [ ] New \`threat_intel_indicators\` table
- [ ] Integrate into entity enrichment
- [ ] Dashboard: TI match badge on entities
- [ ] Feed management API
- [ ] Stats: counts by source, type, freshness
- [ ] Deduplication across feeds"

ci "Investigation cache optimization — Redis + semantic dedup" "M5: Intelligence & RAG" "backend,worker,priority:medium" \
"## Description
Cache uses exact SHA-256 match. Add semantic deduplication for similar alerts.

## Acceptance Criteria
- [ ] Semantic cache: embed alert, search similar cached (threshold 0.95)
- [ ] Cache hit: return cached verdict without workflow
- [ ] L1: Redis exact match (1h), L2: pgvector semantic (24h)
- [ ] Stats: hit rate, miss rate, savings
- [ ] Invalidation endpoint
- [ ] Prometheus: cache_hits_total, cache_misses_total
- [ ] Dashboard: cache performance panel
- [ ] Bypass: \`force_reinvestigate=true\`"

echo ""
echo "=== M6: Testing & Quality ==="

ci "End-to-end test suite with docker-compose" "M6: Testing & Quality" "testing,priority:high" \
"## Description
No E2E tests verify the complete flow from API to sandbox to results.

## Acceptance Criteria
- [ ] Python E2E framework against live docker-compose
- [ ] Tests: task submit, SIEM webhook, file upload, approval flow, playbook resolution, entity extraction, memory enrichment
- [ ] CI: run on PR merge to master
- [ ] Timeout: 5 minutes max
- [ ] JUnit XML output
- [ ] Dedicated \`e2e-test\` tenant
- [ ] Directory: \`tests/e2e/\`"

ci "Mock LLM server for offline testing" "M6: Testing & Quality" "testing,priority:high" \
"## Description
Tests require GPU (vLLM). Create mock LLM server for CPU-only CI.

## Acceptance Criteria
- [ ] OpenAI-compatible \`/v1/chat/completions\` and \`/v1/embeddings\`
- [ ] Deterministic mode: same prompt = same response
- [ ] Canned responses for each prompt template
- [ ] Realistic usage object
- [ ] Configurable latency (default 100ms)
- [ ] Configurable error rate
- [ ] Docker: \`hydra-mock-llm\` with \`--profile test\`
- [ ] \`HYDRA_LLM_MOCK=true\` env variable
- [ ] Directory: \`tests/mock_llm/\`"

ci "Sandbox escape test suite" "M6: Testing & Quality" "testing,security,priority:high" \
"## Description
4 security layers but no automated tests verify they block malicious code.

## Acceptance Criteria
- [ ] Categories: import bypass, network access, filesystem escape, process execution, resource exhaustion, info disclosure
- [ ] Each test verifies blocked by which layer (AST/seccomp/network/timer)
- [ ] 30+ distinct escape attempts
- [ ] Regression: run on every CI build
- [ ] Report: attack matrix with block status
- [ ] Directory: \`tests/security/\`"

ci "Code coverage tracking with pytest-cov" "M6: Testing & Quality" "testing,priority:medium" \
"## Description
No coverage measurement. Add pytest-cov with CI enforcement.

## Acceptance Criteria
- [ ] Add \`pytest-cov\` to worker requirements
- [ ] Config in \`pyproject.toml\`
- [ ] CI: coverage report on every PR
- [ ] Minimum threshold: 40% (increase over time)
- [ ] HTML report as CI artifact
- [ ] Coverage badge in README
- [ ] Branch coverage tracking"

ci "Load test automation in CI — performance regression gate" "M6: Testing & Quality" "testing,performance,priority:medium" \
"## Description
Load tests run manually. Automate in CI to catch regressions. Baseline: 17 inv/min.

## Acceptance Criteria
- [ ] CI job on master merges
- [ ] Metrics: throughput, p50/p95/p99 latency, error rate
- [ ] Gate: fail if throughput drops >20% or errors >5%
- [ ] Baseline in \`tests/benchmarks/baseline.json\`
- [ ] Results as CI artifact
- [ ] Current vs baseline comparison"

ci "Accuracy validation in CI — 50-alert corpus gate" "M6: Testing & Quality" "testing,priority:high" \
"## Description
50 labeled alerts exist but don't gate CI. Wire accuracy testing to catch LLM regression.

## Acceptance Criteria
- [ ] Run on master merges
- [ ] Metrics: verdict accuracy, FP rate, FN rate, avg confidence
- [ ] Gate: fail if accuracy < 70%
- [ ] Per-category breakdown
- [ ] Confusion matrix: TP, FP, TN, FN
- [ ] Dashboard: accuracy trend chart (admin)
- [ ] Expand: 10 new alerts per sprint"

echo ""
echo "=== M7: Deployment & Scale ==="

ci "Container registry — automated Docker image builds" "M7: Deployment & Scale" "deployment,priority:high" \
"## Description
CI builds but doesn't push to registry. Deployments require building from source.

## Acceptance Criteria
- [ ] Push to \`ghcr.io/7inaydas-cmyk/hydra-mvp/{service}:{tag}\`
- [ ] Services: api, worker, dashboard, mock-llm
- [ ] Tags: latest, v{semver}, sha-{commit}
- [ ] Platform: linux/amd64
- [ ] CI: push on master merge and tag
- [ ] Trivy scan before push (fail on critical CVEs)
- [ ] Multi-stage builds, .dockerignore
- [ ] Update docker-compose to reference registry images"

ci "Helm chart for Kubernetes deployment" "M7: Deployment & Scale" "deployment,priority:medium" \
"## Description
K8s uses Kustomize only. Helm provides better templating and release management.

## Acceptance Criteria
- [ ] Chart: \`helm/hydra/\`
- [ ] \`values.yaml\` with sane defaults
- [ ] Templates: Deployments, StatefulSets, Services, Ingress, HPA, NetworkPolicy
- [ ] Sub-charts: PostgreSQL, Redis (bitnami, optional)
- [ ] Values: dev, prod, airgap
- [ ] \`helm test hydra\` runs health checks
- [ ] Parameter table in README
- [ ] Publish to OCI registry"

ci "Blue-green deployment automation" "M7: Deployment & Scale" "deployment,priority:medium" \
"## Description
Updates require downtime. Implement blue-green for zero-downtime.

## Acceptance Criteria
- [ ] \`scripts/deploy-blue-green.sh\`
- [ ] Deploy new alongside current
- [ ] Health check before switching
- [ ] Reverse proxy switches upstream
- [ ] Workers: graceful drain
- [ ] Rollback: one-command switch back
- [ ] DB migrations: backward-compatible, run before switch
- [ ] K8s: RollingUpdate with maxSurge=1, maxUnavailable=0"

ci "Multi-region deployment architecture" "M7: Deployment & Scale" "deployment,architecture,priority:low" \
"## Description
Single-region only. Design multi-region for global SOC teams with data residency.

## Acceptance Criteria
- [ ] Architecture document: topology (active-active vs active-passive)
- [ ] Data residency: tenant data in configured region
- [ ] PostgreSQL logical replication
- [ ] Global load balancer routing
- [ ] Per-region Temporal clusters
- [ ] Tenant config: \`data_region\` field
- [ ] Document trade-offs: consistency vs latency"

ci "Disaster recovery runbook and automated failover" "M7: Deployment & Scale" "deployment,priority:high" \
"## Description
No DR plan. Create runbook and automate recovery.

## Acceptance Criteria
- [ ] Runbook: \`docs/DISASTER_RECOVERY.md\`
- [ ] Scenarios: server crash, DB corruption, network partition, GPU failure
- [ ] RPO: 1 hour, RTO: 30 minutes
- [ ] \`scripts/disaster-recovery.sh\` — automated restore
- [ ] GPU failure: Ollama/CPU fallback
- [ ] Communication template
- [ ] Quarterly DR drill procedure"

ci "Infrastructure as Code — Terraform modules" "M7: Deployment & Scale" "deployment,priority:low" \
"## Description
Cloud deployments manual. Create Terraform for AWS.

## Acceptance Criteria
- [ ] Module: \`terraform/aws/\`
- [ ] Resources: VPC, EKS, RDS, ElastiCache, S3, ECR, ALB, Route53
- [ ] GPU: g4dn.xlarge for vLLM
- [ ] Variables: region, instance types, domain
- [ ] S3 backend with DynamoDB locking
- [ ] Cost estimate in plan output
- [ ] Clean destroy"

echo ""
echo "=== M8: Workflow Automation ==="

ci "Auto-trigger response playbooks on investigation completion" "M8: Workflow Automation" "backend,worker,priority:high" \
"## Description
ResponsePlaybookWorkflow exists but never auto-triggered. Wire to investigation completion.

## Acceptance Criteria
- [ ] After ExecuteTaskWorkflow with true_positive: query matching playbooks, start ResponsePlaybookWorkflow
- [ ] Trigger matching: playbook conditions vs alert metadata
- [ ] Priority ordering: highest-priority first
- [ ] Dry-run mode: tenant setting
- [ ] Dedup by investigation_id + playbook_id
- [ ] Audit: response_auto_triggered event
- [ ] Dashboard: triggered actions on investigation detail
- [ ] Per-tenant enable/disable"

ci "Scheduled workflow execution — cron-based detection and SRE" "M8: Workflow Automation" "backend,worker,priority:high" \
"## Description
Detection and SRE workflows exist but manual-only. Add Temporal schedules.

## Acceptance Criteria
- [ ] DetectionGenerationWorkflow: daily 03:00 UTC
- [ ] SelfHealingWorkflow: every 30 min (dry-run)
- [ ] CrossTenantRefreshWorkflow: hourly
- [ ] Schedule management API: CRUD, pause, resume, list
- [ ] Config in \`tenants.settings\` JSONB
- [ ] Dashboard: schedule management (admin)

## Technical Notes
- Temporal Schedules API
- Default schedules on worker startup"

ci "Alert correlation engine — group related alerts into incidents" "M8: Workflow Automation" "backend,worker,priority:high" \
"## Description
Each SIEM alert creates separate investigation. Related alerts should be correlated into incidents.

## Acceptance Criteria
- [ ] Rules: same source_ip (15min), same MITRE technique (1h), same entity cluster
- [ ] New \`incidents\` table
- [ ] On new alert: check for matching open incidents
- [ ] Match: add to existing incident, enrich context
- [ ] No match: create new incident
- [ ] Escalation: alert count threshold upgrades severity
- [ ] Dashboard: incident list, detail with correlated alerts
- [ ] API: list, detail, merge endpoints
- [ ] Correlated context enriches LLM prompt"

ci "Investigation SLA monitoring and escalation" "M8: Workflow Automation" "backend,priority:medium" \
"## Description
No SLA tracking for investigation completion. Add configurable SLAs with escalation.

## Acceptance Criteria
- [ ] SLA config: critical=15m, high=1h, medium=4h, low=24h
- [ ] Monitor agent_tasks for breaches
- [ ] Escalation: notification, priority boost, reassignment
- [ ] Status: within_sla, warning (80%), breached
- [ ] Dashboard: SLA compliance widget
- [ ] API: \`GET /api/v1/sla/compliance\`
- [ ] Prometheus: \`hydra_sla_breached_total{severity}\`
- [ ] Check every 5 minutes"

ci "Auto-retrain trigger — accuracy-driven model update" "M8: Workflow Automation" "backend,worker,priority:medium" \
"## Description
Fine-tuning never auto-triggers. Start retraining when accuracy drops.

## Acceptance Criteria
- [ ] Weekly accuracy check from investigation_feedback
- [ ] Trigger: accuracy < 75% over last 100 investigations
- [ ] Guard: max 1 run per week
- [ ] Pipeline: export, score, evaluate, compare, promote
- [ ] Notify admin with metrics
- [ ] Rollback if new model worse
- [ ] Dashboard: accuracy trend, retrain history"

echo ""
echo "=== COMPLETE ==="
echo "Total issues created: $CREATED (plus #1 already created = $((CREATED + 1)) total)"
