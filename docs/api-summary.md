# HYDRA API Gateway -- Exhaustive Code Summary

## File-by-File Breakdown

---

### 1. `auth.go`

#### Structs

| Struct | Fields | Purpose |
|--------|--------|---------|
| `RegisterRequest` | `Email` (string, required, email), `Password` (string, required, min=6), `DisplayName` (string, required), `TenantID` (string, required) | JSON body for user registration |
| `LoginRequest` | `Email` (string, required, email), `Password` (string, required) | JSON body for user login |
| `CustomClaims` | `TenantID` (string), `UserID` (string), `Email` (string), `Role` (string), embeds `jwt.RegisteredClaims` | JWT token claims payload |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `registerHandler` | `c *gin.Context` | Validates `RegisterRequest` JSON body. Hashes password with bcrypt (default cost). Generates UUID user ID. Inserts user into `users` table with role `"analyst"`. Returns 201 with user info. |
| `loginHandler` | `c *gin.Context` | Validates `LoginRequest` JSON body. Queries `users` table by email. Checks account lockout via `checkAccountLocked()`. Compares bcrypt hash; on failure calls `recordFailedLogin()`. On success calls `recordSuccessfulLogin()`. Issues HS256 JWT with 24-hour expiry containing tenant_id, user_id, email, role. Returns 200 with token + user info. |

#### Endpoints Registered

None directly -- registered in `main.go`.

---

### 2. `db.go`

#### Structs

None.

#### Package-level Variables

| Variable | Type | Purpose |
|----------|------|---------|
| `dbPool` | `*pgxpool.Pool` | Global PostgreSQL connection pool |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `initDB` | `dbURL string` | Creates a pgxpool connection pool from the given database URL and pings to verify connectivity. Returns error on failure. |
| `closeDB` | (none) | Closes the database pool if non-nil. |

---

### 3. `feedback.go`

#### Structs

| Struct | Fields | Purpose |
|--------|--------|---------|
| `FeedbackRequest` | `VerdictCorrect` (*bool), `CorrectedVerdict` (string), `FalsePositive` (bool), `MissedThreat` (bool), `Notes` (string), `AnalystConfidence` (*float64) | JSON body for analyst feedback on investigations |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `submitFeedbackHandler` | `c *gin.Context` | Extracts investigation ID from URL param `:id`. Validates UUID format. Parses `FeedbackRequest` body. Gets tenant_id and user_id from auth context. Inserts feedback into `investigation_feedback` table. Asynchronously refreshes `feedback_accuracy` materialized view. Returns 201 with feedback ID. |
| `getFeedbackStatsHandler` | `c *gin.Context` | Gets tenant_id from auth context. Queries aggregate stats from `investigation_feedback`: total, correct, incorrect, false positives, missed threats, accuracy rate, avg analyst confidence. Returns 200 with stats JSON. |

---

### 4. `handlers.go`

#### Structs

| Struct | Fields | Purpose |
|--------|--------|---------|
| `TaskRequest` | `TaskType` (string), `Input` (map[string]interface{}, required) | JSON body for task creation |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `healthCheckHandler` | `c *gin.Context` | Returns system health: version "1.0.0", uptime, deployment mode, LLM provider/model info, embedding provider. Pings DB, LiteLLM (`/health/liveliness`), and embedding server (`/health`). Returns 200 with service status map. |
| `createTaskHandler` | `c *gin.Context` | Parses `TaskRequest`. Gets tenant_id from JWT context. Resolves playbook if `playbook_id` in input (queries `playbooks` table, injects steps and system prompt override). Defaults task_type to `"log_analysis"`. Computes SHA-256 alert fingerprint for deduplication (tenant_id + task_type + prompt + source_ip + dest_ip). Checks `alert_fingerprints` table for existing match within dedup window -- if found, returns 200 with `"deduplicated"` status and increments count. Otherwise: generates UUID task ID, inserts fingerprint record, inserts into `agent_tasks`, writes audit log, starts Temporal workflow `"ExecuteTaskWorkflow"` on queue `"hydra-tasks"`. Returns 202 with task_id, workflow_id. |
| `getTaskHandler` | `c *gin.Context` | Gets task by `:id` URL param scoped to tenant. Queries `agent_tasks` for status, type, input, output, timestamps, token usage, execution_ms, severity. Also queries `agent_task_steps` for step count/current step and `approval_requests` for pending approval info. Returns 200 with full task detail. |
| `listTasksHandler` | `c *gin.Context` | Lists tasks for tenant with filtering (search, status, severity, task_type, date_from, date_to), sorting (created_at, status, severity with whitelist), and pagination (page, limit max 100). Counts total, fetches page from `agent_tasks`. Returns 200 with tasks array, total, page, limit, pages. |
| `getTaskAuditHandler` | `c *gin.Context` | Gets audit trail for task `:id` scoped to tenant. Queries `agent_audit_log` by resource_id and tenant_id ordered by created_at ASC. Returns 200 with audit_trail array. |
| `getStatsHandler` | `c *gin.Context` | Aggregates dashboard statistics for tenant: total/completed/failed/pending/executing tasks, token usage, task type distribution, SIEM alert counts (total/new/investigating), and 10 most recent activities. Returns 200 with stats JSON. |
| `uploadTaskHandler` | `c *gin.Context` | Handles multipart file upload (max 10MB). Validates extension (.csv, .json, .txt, .log). Reads up to 50KB of file content for LLM context. Creates task with file data as input, default prompt "Analyze this log file for security anomalies and threats". Inserts into `agent_tasks`, writes audit log, starts Temporal workflow. Returns 201 with task_id, workflow_id, filename, file_size. |
| `getTaskStepsHandler` | `c *gin.Context` | Gets investigation steps for task `:id`. Verifies task belongs to tenant. Queries `investigation_steps` ordered by step_number ASC. Returns each step's id, step_number, step_type, prompt, generated_code, output, status, token usage, execution_ms, timestamps, execution_mode, parameters_used. Returns 200 with steps array. |
| `getPendingApprovalsHandler` | `c *gin.Context` | Lists pending approval requests for tenant. Joins `approval_requests` with `agent_tasks`. Returns approval details including id, task_id, step_number, risk_level, action_summary, generated_code, task_type, prompt, severity. Returns 200 with approvals array and count. |
| `decideApprovalHandler` | `c *gin.Context` | Processes approval decision for `:id`. Validates approval belongs to tenant and is pending. Updates `approval_requests` with approved/rejected status, decided_at, decided_by, comment. Sends `"approval_decision"` signal to Temporal workflow `"task-{taskID}"`. Writes audit log entry. Returns 200 with decision status. |
| `getMeHandler` | `c *gin.Context` | Returns current authenticated user info (id, role, tenant_id) from JWT context. Returns 200. |
| `listSkillsHandler` | `c *gin.Context` | Lists all active skills from `agent_skills` table ordered by times_used DESC. Returns skill details: id, name, slug, threat_types, mitre_tactics, mitre_techniques, severity_default, investigation_methodology, detection_patterns, example_prompt, times_used, version, is_community, has_template. Returns 200 with skills array and count. |
| `getNotificationsHandler` | `c *gin.Context` | Fetches recent notifications for tenant. Accepts `since` query param (RFC3339, defaults to 60 seconds ago). Queries `agent_audit_log` for task_completed and approval_requested events. Queries `siem_alerts` for new alerts. Merges and sorts by timestamp descending. Returns 200 with notifications array. |
| `getTaskTimelineHandler` | `c *gin.Context` | Builds chronological timeline for task `:id`. Includes: task creation/completion events, investigation steps (start/complete/fail), audit log entries (approvals, skill retrievals). Sorts by timestamp ascending. Returns 200 with timeline array. |

---

### 5. `main.go`

#### Structs

| Struct | Fields | Purpose |
|--------|--------|---------|
| `Config` | `Port` (string), `DatabaseURL` (string), `TemporalAddress` (string), `LiteLLMMasterKey` (string), `JWTSecret` (string) | Application configuration loaded from environment |

#### Package-level Variables

| Variable | Type | Purpose |
|----------|------|---------|
| `appConfig` | `*Config` | Global application configuration |
| `startTime` | `time.Time` | Server start time for uptime calculation |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `init` | (none) | Go init function. Populates `appConfig` from environment variables with defaults: PORT=8090, DATABASE_URL=postgresql://hydra:hydra_dev_2026@postgres:5432/hydra, TEMPORAL_ADDRESS=temporal:7233, LITELLM_MASTER_KEY="", JWT_SECRET=hydra-jwt-secret-dev-2026. |
| `getEnvOrDefault` | `key string, fallback string` | Returns environment variable value if set, otherwise returns fallback. |
| `main` | (none) | Entry point. Initializes DB (`initDB`), Temporal client (`initTemporal`). Creates Gin router with `gin.Default()`. Attaches global middleware: `corsMiddleware()`, `securityHeadersMiddleware()`, `loggingMiddleware()`. Registers all routes (see endpoint map below). Starts HTTP server on configured port. |

#### All Route Registrations (defined in `main()`)

See the complete endpoint map table at the end of this document.

---

### 6. `middleware.go`

#### Structs

None.

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `loggingMiddleware` | (none) returns `gin.HandlerFunc` | Logs every request: method, path, HTTP status code, and latency duration. Runs before and after handler (wraps `c.Next()`). |
| `corsMiddleware` | (none) returns `gin.HandlerFunc` | Configures CORS: allows origin `http://localhost:3000`, allows credentials, allows headers Origin/Content-Length/Content-Type/Authorization. Uses `gin-contrib/cors`. |
| `authMiddleware` | (none) returns `gin.HandlerFunc` | Extracts Bearer token from Authorization header. Parses JWT with `CustomClaims` using `appConfig.JWTSecret`. Allows expired tokens (for dev convenience) but rejects invalid signatures. Injects `tenant_id`, `user_id`, `user_role` into Gin context. Aborts with 401 on missing/invalid token. |
| `requireRole` | `allowedRoles ...string` returns `gin.HandlerFunc` | Checks `user_role` from Gin context against allowed roles. Aborts with 403 if role not in allowed list. |

---

### 7. `models.go`

#### Structs

| Struct | Fields | Purpose |
|--------|--------|---------|
| (inline in `createModelHandler`) | `Name` (string, required), `Provider` (string, required), `ModelID` (string, required), `Version` (string), `IsDefault` (bool), `Config` (map), `RoutingRules` (map) | Request body for model creation |
| (inline in `updateModelHandler`) | `Name` (*string), `Status` (*string), `IsDefault` (*bool), `Config` (map), `RoutingRules` (map) | Request body for model update |
| (inline in `createABTestHandler`) | `Name` (string, required), `ModelAID` (string, required), `ModelBID` (string, required), `TrafficSplit` (float64) | Request body for A/B test creation |
| (inline in `completeABTestHandler`) | `WinnerID` (string, required), `Promote` (bool) | Request body for completing A/B test |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `listModelsHandler` | `c *gin.Context` | Lists all models from `model_registry` ordered by created_at DESC. Returns model details: id, name, provider, model_id, version, status, is_default, config, routing_rules, eval_score, created_at. Returns 200 with models array and count. |
| `createModelHandler` | `c *gin.Context` | Creates a model registry entry. Defaults version to "1.0", config/routing_rules to empty maps. If `is_default=true`, clears existing default. Inserts into `model_registry`. Returns 201 with model summary. |
| `updateModelHandler` | `c *gin.Context` | Updates model `:id` fields selectively (name, status, is_default, config, routing_rules). If promoting to default, clears existing default and sets status to "promoted". Returns 200 with status "updated". |
| `listABTestsHandler` | `c *gin.Context` | Lists all A/B tests from `model_ab_tests` joined with `model_registry` for model names. Returns test details: id, name, traffic_split, status, model names, results, winner, timestamps. Returns 200 with ab_tests array and count. |
| `createABTestHandler` | `c *gin.Context` | Creates an A/B test between two models. Defaults traffic_split to 0.5 if out of (0,1) range. Inserts into `model_ab_tests`. Marks both models as status "testing". Returns 201 with test summary. |
| `completeABTestHandler` | `c *gin.Context` | Completes A/B test `:id` with a winner. Updates test to "completed" with winner_id and completed_at. If `promote=true`, promotes winner to default model. Returns 200 with completion status. |

---

### 8. `playbooks.go`

#### Structs

| Struct | Fields | Purpose |
|--------|--------|---------|
| `Playbook` | `ID` (string), `TenantID` (*string), `Name` (string), `Description` (string), `Icon` (string), `TaskType` (string), `IsTemplate` (bool), `SystemPromptOverride` (*string), `Steps` ([]string), `CreatedBy` (*string), `CreatedAt` (time.Time), `UpdatedAt` (time.Time) | Full playbook model |
| `CreatePlaybookRequest` | `Name` (string, required), `Description` (string), `Icon` (string), `TaskType` (string, required), `SystemPromptOverride` (*string), `Steps` ([]string, required, min=1, max=3) | Request body for creating/updating playbooks |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `listPlaybooksHandler` | `c *gin.Context` | Lists playbooks visible to tenant (own playbooks + templates). Queries `playbooks` table with `tenant_id = X OR is_template = true`, ordered by is_template DESC then created_at DESC. Deserializes steps JSON. Returns 200 with playbook array. |
| `createPlaybookHandler` | `c *gin.Context` | Creates a new playbook for the tenant. Defaults icon to magnifying glass emoji. Serializes steps to JSON. Inserts with `is_template = false`. Returns 201 with full playbook object via RETURNING clause. |
| `updatePlaybookHandler` | `c *gin.Context` | Updates playbook `:id` owned by tenant. Only non-template playbooks can be edited (`is_template = false`). Updates name, description, icon, task_type, system_prompt_override, steps. Returns 200 or 404 if not found/template. |
| `deletePlaybookHandler` | `c *gin.Context` | Deletes playbook `:id` owned by tenant. Only non-template playbooks can be deleted. Returns 200 or 404. |

---

### 9. `security.go`

#### Structs

| Struct | Fields | Purpose |
|--------|--------|---------|
| `rateLimiter` | `mu` (sync.Mutex), `attempts` (map[string][]time.Time), `window` (time.Duration), `limit` (int) | In-memory per-key rate limiter using sliding window |

#### Package-level Variables

| Variable | Type | Purpose |
|----------|------|---------|
| `authLimiter` | `*rateLimiter` | Global auth rate limiter: 10 attempts per 15 minutes per IP |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `securityHeadersMiddleware` | (none) returns `gin.HandlerFunc` | Sets security headers on every response: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, X-XSS-Protection: 1; mode=block, Referrer-Policy: strict-origin-when-cross-origin, Cache-Control: no-store/no-cache/must-revalidate, Pragma: no-cache. |
| `(rl *rateLimiter).allow` | `key string` returns `bool` | Sliding window rate limit check. Cleans expired entries, checks if count >= limit. Adds current timestamp if allowed. Thread-safe via mutex. |
| `authRateLimitMiddleware` | (none) returns `gin.HandlerFunc` | Applies `authLimiter` per client IP. Aborts with 429 if rate exceeded. |
| `auditMiddleware` | (none) returns `gin.HandlerFunc` | Post-handler middleware. Only fires on successful (< 400) mutating requests (POST, PUT, DELETE). Logs to `agent_audit_log` asynchronously (goroutine) with method, path, status, IP. |
| `checkAccountLocked` | `email string` returns `bool` | Queries `users.locked_until` for the given email. Returns true if locked_until is in the future. |
| `recordFailedLogin` | `email string` | Increments `failed_login_attempts` for user. If attempts >= 5, locks account for 30 minutes by setting `locked_until`. |
| `recordSuccessfulLogin` | `email string` | Resets `failed_login_attempts` to 0, clears `locked_until`, updates `last_login_at` to NOW(). |
| `listRetentionPoliciesHandler` | `c *gin.Context` | Lists all data retention policies from `data_retention_policies` ordered by table_name. Returns id, table_name, retention_days, delete_strategy, is_active, last_cleanup_at, rows_cleaned. Returns 200 with policies array and count. |
| `updateRetentionPolicyHandler` | `c *gin.Context` | Updates retention policy `:id`. Supports partial update of `retention_days` and `is_active`. Returns 200 with status "updated". |

---

### 10. `siem.go`

#### Structs

None (inline structs used in handler functions).

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `webhookAlertHandler` | `c *gin.Context` | Public webhook receiver for SIEM alerts. Looks up `log_sources` by `:source_id` URL param. Validates source is active. Reads raw body. Validates HMAC-SHA256 signature (header `X-Webhook-Signature`) if webhook_secret configured in connection_config. Parses JSON payload. Normalizes via `normalizeSIEMAlert()`. Inserts into `siem_alerts` with status "new". Updates log_source event count. Auto-investigates if configured (calls `autoInvestigateAlert()`). Returns 200 with alert_id, investigation_id, status. |
| `normalizeSIEMAlert` | `payload map[string]interface{}` returns `map[string]interface{}` | Normalizes SIEM alert payloads from different formats: Splunk (has `search_name` + `result`), Elastic/Kibana (has `rule.id` + `kibana.alert`), or generic (direct `alert_name`, `severity`, etc.). Returns normalized map with keys: alert_name, severity, source_ip, dest_ip, rule_name. |
| `autoInvestigateAlert` | `ctx context.Context, tenantID string, alertID string, normalized map[string]interface{}` returns `(string, error)` | Creates an auto-investigation task for a SIEM alert. Maps severity to task_type (critical/high -> incident_response, medium -> threat_hunt, else -> log_analysis). Generates prompt from alert fields. Inserts task into `agent_tasks`. Starts Temporal workflow. Links alert to task by updating `siem_alerts.task_id`. Writes audit log. Returns task ID. |
| `listLogSourcesHandler` | `c *gin.Context` | Lists log sources for tenant from `log_sources` table. Returns id, name, source_type, connection_config, is_active, last_event_at, event_count, created_at, and computed webhook_url. Returns 200 with sources array and count. |
| `createLogSourceHandler` | `c *gin.Context` | Creates a log source for tenant. Requires name and source_type. Generates UUID. Inserts into `log_sources`. Returns 201 with source info including webhook_url. |
| `updateLogSourceHandler` | `c *gin.Context` | Updates log source `:id` for tenant. Verifies ownership. Supports partial update of name, connection_config, is_active. Returns 200 with status "updated" or 404. |
| `deleteLogSourceHandler` | `c *gin.Context` | Soft-deletes log source `:id` by setting `is_active = false`. Verifies tenant ownership. Returns 200 with status "deactivated" or 404. |
| `listSIEMalertsHandler` | `c *gin.Context` | Lists SIEM alerts for tenant with optional filtering by status and source_id query params. Ordered by created_at DESC, limited to 50. Returns alert details: id, log_source_id, task_id, alert_name, severity, IPs, rule_name, status, auto_investigate, created_at. Returns 200 with alerts array and count. |
| `investigateAlertHandler` | `c *gin.Context` | Manually triggers investigation for SIEM alert `:id`. Verifies alert belongs to tenant and has status "new". Calls `autoInvestigateAlert()`. Returns 200 with alert_id, investigation_id, status "investigating". |

---

### 11. `temporal.go`

#### Structs

None.

#### Package-level Variables

| Variable | Type | Purpose |
|----------|------|---------|
| `tc` | `client.Client` | Global Temporal SDK client |

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `initTemporal` | `address string` returns `error` | Dials the Temporal server at the given address and stores the client in `tc`. |
| `closeTemporal` | (none) | Closes the Temporal client if non-nil. |

---

### 12. `tenants.go`

#### Structs

None (inline structs used in handler functions).

#### Functions

| Function | Parameters | Description |
|----------|-----------|-------------|
| `listTenantsHandler` | `c *gin.Context` | Lists all tenants from `tenants` table ordered by created_at DESC. Returns id, name, slug, tier, settings, is_active, max_concurrent, created_at. Returns 200 with tenants array and count. |
| `getTenantHandler` | `c *gin.Context` | Gets tenant by `:id` with additional user_count and task_count aggregates. Returns 200 with full tenant detail or 404. |
| `createTenantHandler` | `c *gin.Context` | Creates a tenant. Requires name and slug. Defaults tier to "free", max_concurrent to 50. Generates UUID. Inserts into `tenants`. Returns 201 with tenant summary. Returns 409 on duplicate slug. |
| `updateTenantHandler` | `c *gin.Context` | Updates tenant `:id` fields selectively (name, tier, settings, is_active, max_concurrent). Verifies tenant exists. Returns 200 with status "updated" or 404. |
| `generateSecret` | (none) returns `string` | Generates a 32-byte random secret encoded as hex (64 chars). Used for webhook endpoint secrets. |
| `listWebhookEndpointsHandler` | `c *gin.Context` | Lists webhook endpoints for tenant from `webhook_endpoints` table. Returns id, name, url, event_types, is_active, created_at. Returns 200 with endpoints array and count. |
| `createWebhookEndpointHandler` | `c *gin.Context` | Creates a webhook endpoint. Requires name, url, event_types. Validates event_types against whitelist: investigation_completed, alert_received, approval_needed, response_executed. Generates UUID and random secret. Inserts into `webhook_endpoints`. Returns 201 with endpoint info including secret (shown only at creation). |
| `updateWebhookEndpointHandler` | `c *gin.Context` | Updates webhook endpoint `:id` for tenant. Supports partial update of name, url, event_types, is_active. Verifies ownership. Returns 200 with status "updated" or 404. |
| `deleteWebhookEndpointHandler` | `c *gin.Context` | Soft-deletes webhook endpoint `:id` by setting `is_active = false`. Verifies tenant ownership. Returns 200 with status "deactivated" or 404. |
| `listWebhookDeliveriesHandler` | `c *gin.Context` | Lists webhook delivery attempts for tenant from `webhook_deliveries` table, limited to 50 most recent. Returns id, endpoint_id, event_type, status, http_status, attempts, created_at. Returns 200 with deliveries array and count. |
| `DispatchWebhook` | `tenantID string, eventType string, payload map[string]interface{}` | Queries active webhook endpoints for tenant matching the event_type. Spawns a goroutine per endpoint to deliver the webhook asynchronously. |
| `deliverWebhook` | `tenantID string, endpointID string, url string, secret string, eventType string, payload map[string]interface{}` | Creates a delivery record in `webhook_deliveries`. Attempts delivery up to 3 times with exponential backoff (1s, 4s). Marks as "delivered" or "failed". |
| `attemptDelivery` | `url string, secret string, body []byte` returns `(int, error)` | Makes an HTTP POST to the webhook URL with JSON body. Sets Content-Type, User-Agent ("HYDRA-Webhook/1.0"), and HMAC-SHA256 signature header if secret configured. 10-second timeout. Returns HTTP status code. |

---

## Middleware Chain

The middleware chain is applied in this order (defined in `main.go`):

### Global Middleware (applied to ALL routes)

| Order | Middleware | Source | Description |
|-------|-----------|--------|-------------|
| 1 | `gin.Default()` built-ins | Gin framework | Includes Gin's built-in `Logger()` and `Recovery()` middleware |
| 2 | `corsMiddleware()` | `middleware.go` | CORS handling: allows localhost:3000, credentials, auth headers |
| 3 | `securityHeadersMiddleware()` | `security.go` | Adds X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Cache-Control, Pragma headers |
| 4 | `loggingMiddleware()` | `middleware.go` | Logs [METHOD] path status latency for every request |

### Auth Routes (`/api/v1/auth/*`)

| Order | Middleware | Source | Description |
|-------|-----------|--------|-------------|
| 5 | `authRateLimitMiddleware()` | `security.go` | In-memory sliding window: 10 requests per 15 minutes per IP |

### Protected Routes (`/api/v1/*` except auth)

| Order | Middleware | Source | Description |
|-------|-----------|--------|-------------|
| 5 | `authMiddleware()` | `middleware.go` | JWT Bearer token validation, injects tenant_id/user_id/user_role into context |
| 6 | `auditMiddleware()` | `security.go` | Post-handler: logs successful POST/PUT/DELETE requests to agent_audit_log |

### Role-Restricted Routes

| Order | Middleware | Source | Description |
|-------|-----------|--------|-------------|
| 7 | `requireRole(...)` | `middleware.go` | Per-route RBAC check against user_role in context |

### Public Webhook Route (`POST /api/v1/webhooks/:source_id/alert`)

Only global middleware (1-4). No JWT auth -- uses HMAC-SHA256 signature validation instead.

---

## Complete Endpoint Map

| Method | Path | Handler | Auth Required | Role Restriction |
|--------|------|---------|:-------------:|:----------------:|
| GET | `/health` | `healthCheckHandler` | No | None |
| POST | `/api/v1/auth/login` | `loginHandler` | No (rate limited) | None |
| POST | `/api/v1/auth/register` | `registerHandler` | No (rate limited) | None |
| POST | `/api/v1/webhooks/:source_id/alert` | `webhookAlertHandler` | No (HMAC-validated) | None |
| GET | `/api/v1/tasks` | `listTasksHandler` | Yes | Any authenticated |
| GET | `/api/v1/tasks/:id` | `getTaskHandler` | Yes | Any authenticated |
| GET | `/api/v1/tasks/:id/audit` | `getTaskAuditHandler` | Yes | Any authenticated |
| GET | `/api/v1/tasks/:id/steps` | `getTaskStepsHandler` | Yes | Any authenticated |
| GET | `/api/v1/tasks/:id/timeline` | `getTaskTimelineHandler` | Yes | Any authenticated |
| GET | `/api/v1/stats` | `getStatsHandler` | Yes | Any authenticated |
| GET | `/api/v1/playbooks` | `listPlaybooksHandler` | Yes | Any authenticated |
| GET | `/api/v1/skills` | `listSkillsHandler` | Yes | Any authenticated |
| GET | `/api/v1/me` | `getMeHandler` | Yes | Any authenticated |
| GET | `/api/v1/log-sources` | `listLogSourcesHandler` | Yes | Any authenticated |
| GET | `/api/v1/siem-alerts` | `listSIEMalertsHandler` | Yes | Any authenticated |
| GET | `/api/v1/notifications` | `getNotificationsHandler` | Yes | Any authenticated |
| POST | `/api/v1/tasks` | `createTaskHandler` | Yes | admin, analyst |
| POST | `/api/v1/tasks/upload` | `uploadTaskHandler` | Yes | admin, analyst |
| POST | `/api/v1/siem-alerts/:id/investigate` | `investigateAlertHandler` | Yes | admin, analyst |
| POST | `/api/v1/investigations/:id/feedback` | `submitFeedbackHandler` | Yes | admin, analyst |
| GET | `/api/v1/feedback/stats` | `getFeedbackStatsHandler` | Yes | admin |
| GET | `/api/v1/webhooks/endpoints` | `listWebhookEndpointsHandler` | Yes | Any authenticated |
| GET | `/api/v1/webhooks/deliveries` | `listWebhookDeliveriesHandler` | Yes | Any authenticated |
| GET | `/api/v1/approvals/pending` | `getPendingApprovalsHandler` | Yes | admin |
| POST | `/api/v1/approvals/:id/decide` | `decideApprovalHandler` | Yes | admin |
| POST | `/api/v1/playbooks` | `createPlaybookHandler` | Yes | admin |
| PUT | `/api/v1/playbooks/:id` | `updatePlaybookHandler` | Yes | admin |
| DELETE | `/api/v1/playbooks/:id` | `deletePlaybookHandler` | Yes | admin |
| POST | `/api/v1/log-sources` | `createLogSourceHandler` | Yes | admin |
| PUT | `/api/v1/log-sources/:id` | `updateLogSourceHandler` | Yes | admin |
| DELETE | `/api/v1/log-sources/:id` | `deleteLogSourceHandler` | Yes | admin |
| GET | `/api/v1/tenants` | `listTenantsHandler` | Yes | admin |
| GET | `/api/v1/tenants/:id` | `getTenantHandler` | Yes | admin |
| POST | `/api/v1/tenants` | `createTenantHandler` | Yes | admin |
| PUT | `/api/v1/tenants/:id` | `updateTenantHandler` | Yes | admin |
| POST | `/api/v1/webhooks/endpoints` | `createWebhookEndpointHandler` | Yes | admin |
| PUT | `/api/v1/webhooks/endpoints/:id` | `updateWebhookEndpointHandler` | Yes | admin |
| DELETE | `/api/v1/webhooks/endpoints/:id` | `deleteWebhookEndpointHandler` | Yes | admin |
| GET | `/api/v1/models` | `listModelsHandler` | Yes | admin |
| POST | `/api/v1/models` | `createModelHandler` | Yes | admin |
| PUT | `/api/v1/models/:id` | `updateModelHandler` | Yes | admin |
| GET | `/api/v1/models/ab-tests` | `listABTestsHandler` | Yes | admin |
| POST | `/api/v1/models/ab-tests` | `createABTestHandler` | Yes | admin |
| POST | `/api/v1/models/ab-tests/:id/complete` | `completeABTestHandler` | Yes | admin |
| GET | `/api/v1/retention-policies` | `listRetentionPoliciesHandler` | Yes | admin |
| PUT | `/api/v1/retention-policies/:id` | `updateRetentionPolicyHandler` | Yes | admin |

**Total: 44 endpoints** (1 health + 2 auth + 1 public webhook + 40 protected API)
