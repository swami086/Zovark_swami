# Zovark v3.1 — Complete End-to-End Workflow

> Every step a SIEM alert takes from HTTP request to dashboard verdict.
> Traced from actual source code, not documentation.

---

## Overview

```
SIEM Alert (HTTP POST)
    |
    v
[Go API :8090] ── 10 middleware layers ── 3 pre-Temporal filters ── Temporal workflow start
    |
    v
[Temporal Server] ── queues workflow ── dispatches to worker
    |
    v
[Python Worker] ── 6-stage pipeline ── deterministic tools ── structured verdict
    |
    v
[PostgreSQL] ── NOTIFY ── [Go API SSE] ── [React Dashboard]
```

---

## PHASE 1: HTTP INGRESS (Go API)

### 1.1 Network Entry

Alert arrives at `POST /api/v1/tasks` on port 8090 (Gin HTTP server).

**Files:** `api/main.go`, `api/task_handlers.go`

### 1.2 Middleware Chain (10 layers, in order)

Every request passes through these layers before reaching the handler:

| # | Middleware | File | What It Does |
|---|-----------|------|-------------|
| 1 | `corsMiddleware()` | `middleware.go:25` | Checks origin against `ZOVARK_CORS_ORIGINS` (default: `localhost:3000,5173`). Sets CORS headers. |
| 2 | `securityHeadersMiddleware()` | `security.go:19` | Adds 9 security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CSP`, `HSTS`, etc. |
| 3 | `loggingMiddleware()` | `middleware.go:16` | Logs `[METHOD] PATH STATUS LATENCY` for every request. |
| 4 | `maxBodySizeMiddleware(10MB)` | `security.go:42` | Rejects payloads > 10 MB via `http.MaxBytesReader()`. Prevents DoS. |
| 5 | `authMiddleware()` | `middleware.go:46` | Authenticates the request (see 1.3). |
| 6 | `tenantRateLimitMiddleware()` | `ratelimit.go:141` | Per-tenant rate limit: 100 req/min, 1000 req/hour. Redis sliding window + local fallback. Returns 429 + `Retry-After` when exceeded. |
| 7 | `auditMiddleware()` | `security.go:109` | Logs mutating requests (POST/PUT/DELETE) to `agent_audit_log` table asynchronously. |
| 8 | `requireRole("admin","analyst","api_key")` | `middleware.go:105` | Checks `user_role` from JWT claims. Returns 403 if role not in allowed list. |
| 9 | `checkTokenQuota()` | `tokenquota.go:334` | Checks monthly token/cost limits. Returns 429 if quota exceeded or circuit breaker open. |
| 10 | **Handler** | `task_handlers.go:39` | `createTaskHandler()` — business logic starts here. |

### 1.3 Authentication (`authMiddleware`)

**File:** `middleware.go:46-103`

Two authentication methods (tried in order):

**Method A: API Key (M2M)**
1. Check `X-API-Key` header
2. Key format: `zovark_` + base64(32 random bytes)
3. Hash with SHA-256, look up in `api_keys` table
4. Check expiration + scopes
5. Set context: `tenant_id`, `user_id` (key ID), `user_role = "api_key"`

**Method B: JWT Bearer Token**
1. Parse `Authorization: Bearer <token>` header
2. Validate HMAC-SHA256 signature against `JWT_SECRET` (min 32 chars)
3. Extract claims: `tenant_id`, `user_id`, `email`, `role`
4. JWT lifetime: 30 minutes (access), 7 days (refresh via HttpOnly cookie)

### 1.4 Account Security

**File:** `security.go:145-179`

- **Lockout:** 5 failed login attempts → account locked for 30 minutes
- **Auth rate limit:** 10 attempts per 15 minutes per IP (in-memory, resets on API restart)

---

## PHASE 2: PRE-TEMPORAL FILTERING (Go API)

### 2.1 Request Parsing

**File:** `task_handlers.go:39-80`

```go
type TaskRequest struct {
    TaskType string                 `json:"task_type"`
    Input    map[string]interface{} `json:"input" binding:"required"`
}
```

- If `playbook_id` is in input, resolves playbook from DB and overrides `task_type`
- Default `task_type` if empty: `"log_analysis"`

### 2.2 DB-Based Alert Fingerprint Dedup (Sprint 5)

**File:** `task_handlers.go:81-121`

1. Compute SHA-256 fingerprint from: `tenant_id + task_type + prompt + source_ip + dest_ip`
2. Query `alert_fingerprints` table for existing match within `dedup_window_seconds`
3. If found: return HTTP 200 `{"status": "deduplicated", "investigation_id": "..."}` — **no workflow created**
4. If not found: insert new fingerprint record

### 2.3 Layer 1: Redis Pre-Dedup (NEW — burst protection)

**File:** `alert_dedup.go`

1. Compute alert hash: `SHA-256(JSON(rule_name, source_ip, destination_ip, hostname, username, normalized_raw_log))`
   - `normalized_raw_log`: timestamps stripped via 3 regex patterns (ISO 8601, syslog, US date) → `"TIMESTAMP"`
   - Hash is identical to Python `_compute_alert_hash()` in `worker/stages/ingest.py:166`
2. Check Redis key: `dedup:exact:{hash}`
3. If exists: return HTTP 200 `{"status": "deduplicated"}` — **no workflow, no DB write for task**
4. TTL by severity: critical=60s, high=300s, medium=900s, low=3600s, info=7200s
5. **Fail-open:** if Redis unavailable, skip dedup

### 2.4 Layer 2: Batch Buffer (NEW — burst protection)

**File:** `batch_buffer.go`

1. Compute batch key: `SHA-256(task_type + ":" + source_ip)[:16]`
2. Redis key: `apibatch:{batch_key}` (hash type with `task_id`, `count`, `first_ts`)
3. Atomic check via Lua script:
   - **First alert:** creates batch, proceeds to workflow
   - **Subsequent within window:** absorbed, returns HTTP 200 `{"status": "batched"}` — **no workflow**
   - **Window expired or batch full:** new batch, proceeds to workflow
4. Window: 5s default × severity multiplier (critical=0.25x=1.25s, info=3x=15s)
5. Max batch size: 500
6. **Fail-open:** if Redis unavailable, create workflow

### 2.5 Database Insert

**File:** `task_handlers.go:137-174`

1. `beginTenantTx(ctx, tenantID)` — starts PostgreSQL transaction with RLS context:
   ```sql
   SET LOCAL app.current_tenant = '{tenant_id}'
   ```
2. Insert into `agent_tasks`:
   ```sql
   INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at, trace_id)
   VALUES ($1, $2, $3, $4, 'pending', NOW(), $7)
   ```
3. Insert audit log into `agent_audit_log`
4. **COMMIT** — task is now visible to all connections
5. Register dedup hash in Redis (`registerPreDedup`)

### 2.6 Layer 3: Temporal Backpressure (NEW — overload protection)

**File:** `backpressure.go`

1. Track active workflows in Redis sorted set: `temporal:workflow_starts`
2. Count entries in last 120 seconds
3. **Below soft limit (200):** proceed with workflow
4. **Between soft and hard limit (200-1000):** update task to `status='queued'`, return HTTP 202
5. **Above hard limit (1000):** return HTTP 503 + `Retry-After: 30`
6. **Queue drain goroutine:** polls `agent_tasks WHERE status='queued'` every 2 seconds, starts workflows (10 per tick)

### 2.7 Temporal Workflow Start

**File:** `task_handlers.go:176-195`

```go
workflowOptions := client.StartWorkflowOptions{
    ID:        "task-" + taskID,     // deterministic ID
    TaskQueue: "zovark-tasks",       // single queue
}
tc.ExecuteWorkflow(ctx, workflowOptions, workflowName, req)
```

- Workflow ID is `task-{uuid}` (deterministic, prevents double-start)
- Task queue: `zovark-tasks` (all types share one queue)
- If Temporal is down: task marked `failed`, HTTP 500 returned
- On success: HTTP 202 with `task_id`, `workflow_id`, `trace_id`

### 2.8 HTTP Response

```json
{
  "task_id": "bd45ea48-a987-44c0-8268-d7d73a2c2cf5",
  "workflow_id": "task-bd45ea48-a987-44c0-8268-d7d73a2c2cf5",
  "status": "pending",
  "trace_id": "29e1e34b-2cba-43b8-8dc0-e5ce770780c5"
}
```

Header: `X-Zovark-Trace-ID: 29e1e34b-...`

---

## PHASE 3: TEMPORAL ORCHESTRATION

### 3.1 Worker Pickup

**File:** `worker/main.py:99-150`

The Python worker runs a Temporal worker process with:
- Task queue: `zovark-tasks`
- `max_concurrent_workflow_tasks = 32` (configurable via `ZOVARK_MAX_CONCURRENT_WORKFLOWS`)
- `max_concurrent_activities = 16` (configurable via `ZOVARK_MAX_CONCURRENT_ACTIVITIES`)
- 107 registered activities, 17 registered workflows

When Temporal dispatches a workflow, the worker calls `InvestigationWorkflowV2`.

### 3.2 Workflow Orchestrator

**File:** `worker/stages/investigation_workflow.py`

`InvestigationWorkflowV2` calls 7 activities in sequence:

```
fetch_task (30s timeout)
    → ingest_alert (30s timeout)
    → analyze_alert (900s timeout)
    → execute_investigation (60-120s timeout)
    → assess_results (60s timeout)
    → apply_governance (10s timeout)
    → store_investigation (30s timeout)
```

Each activity receives the output of the previous one. If any activity fails, the workflow fails.

The workflow checks `ZOVARK_EXECUTION_MODE`:
- `tools` (default, v3): deterministic tool pipeline
- `sandbox` (legacy, v2): Docker sandbox code execution

---

## PHASE 4: INVESTIGATION PIPELINE (Python Worker)

### Stage 1: INGEST (`worker/stages/ingest.py`)

**Function:** `ingest_alert(data: dict) -> IngestOutput`
**Timeout:** 30 seconds
**LLM calls:** None

**Step-by-step:**

1. **Fetch task** from `agent_tasks` table by `task_id`

2. **Input sanitization** (`worker/stages/input_sanitizer.py`):
   - 25 injection patterns checked (template injection `{{`, code injection `exec(`, SSTI `__class__`, etc.)
   - Unicode normalization: 18 Cyrillic homoglyphs mapped to ASCII (е→e, а→a, о→o, etc.)
   - Zero-width characters stripped (U+200B, U+200C, U+200D, U+FEFF)
   - Field truncation at 10,000 characters
   - Shannon entropy analysis (flags fields > 5.5 bits/char)
   - Tail scanning: checks last 500 chars for injection patterns (prevents field-padding attacks)

3. **Field normalization** (`worker/stages/normalizer.py`):
   - 70+ field mappings across SIEM formats:
     - Splunk: `src_ip` → `source_ip`, `dest_ip` → `destination_ip`
     - Elastic: `source.ip` → `source_ip`, `destination.ip` → `destination_ip`
     - Firewall: `SrcAddr` → `source_ip`, `DstAddr` → `destination_ip`
   - Severity normalization: `1-3` → `low`, `4-6` → `medium`, `7-9` → `high`, `10` → `critical`

4. **Redis dedup** (second layer, Python-side):
   - Same hash algorithm as Go-side: `SHA-256(JSON(rule_name, source_ip, destination_ip, hostname, username, normalized_raw_log))`
   - If duplicate found: set `is_duplicate=True`, workflow exits early
   - If not duplicate: register hash with severity-based TTL

5. **Smart batching** (`worker/stages/smart_batcher.py`):
   - Batch key: `hash(task_type + ":" + source_ip)[:16]`
   - If batch window active for this key: absorb alert, workflow exits early
   - Window: 60 seconds × severity multiplier

6. **PII masking**:
   - 3 regex patterns: AWS keys (`AKIA...`), SSNs (`\d{3}-\d{2}-\d{4}`), API keys/tokens
   - Replaced with placeholder labels (`AWS_KEY`, `SSN`, `API_KEY`)

7. **Skill retrieval** from `agent_skills` table:
   - Query: `SELECT * FROM agent_skills WHERE $task_type = ANY(task_types) AND is_active = true`
   - Returns skill template, methodology, parameters, and `investigation_plan`

8. **Benign routing** (inverted logic):
   - Check `ATTACK_INDICATORS` list (40 terms): `malware`, `trojan`, `ransomware`, `phishing`, `brute`, etc.
   - If task_type/rule_name/title do NOT match any attack indicator → route to `benign-system-event` template
   - **Content-based override** (`_has_raw_log_attack_content`): scan `raw_log` against 54 high-confidence attack patterns. If attack content found, block benign routing → force investigation.

**Output:** `IngestOutput` with `task_id`, `task_type`, `siem_event`, `skill_id`, `skill_template`, `skill_params`, `is_duplicate`, `is_benign`

---

### Stage 2: ANALYZE (`worker/stages/analyze.py`)

**Function:** `analyze_alert(ingest: IngestOutput) -> AnalyzeOutput`
**Timeout:** 900 seconds (15 min, for LLM fallback)
**LLM calls:** 0 (Path A) or 1 (Path C)

**Step-by-step:**

1. **Check execution mode** (`ZOVARK_EXECUTION_MODE`):
   - `tools` (default): v3 deterministic tool pipeline
   - `sandbox`: v2 Docker sandbox (legacy)

2. **For tools mode — Plan resolution** (tried in order):

   **a) Database saved plan:**
   - Query `agent_skills` table for `investigation_plan` column
   - If found: use that plan directly (Path A, ~5ms)

   **b) `investigation_plans.json` lookup:**
   - File: `worker/tools/investigation_plans.json` (24 plans)
   - Try exact match on `task_type` (e.g., `brute_force`)
   - Try **alias mapping** (20 aliases, e.g., `phishing` → `phishing_investigation`, `ransomware` → `ransomware_triage`)
   - Try **substring match** (e.g., `phishing` matches `phishing_investigation`)
   - If benign task_type (31 types like `password_change`, `windows_update`): use `benign_system_event` plan

   **c) LLM tool selection (Path C fallback):**
   - If no plan found and `ZOVARK_MODE != "templates-only"`:
   - Call LLM (llama3.2:3b) with tool catalog to select tools
   - System prompt: "You are Zovark's investigation planner..."
   - Response parsed as JSON tool list
   - Each tool validated against `TOOL_CATALOG`

   **d) Fail-closed:**
   - If LLM is down: return empty plan with `path_taken="error_llm_down"`
   - Circuit breaker goes RED
   - Alert gets `verdict=needs_manual_review` (never benign)

3. **Institutional knowledge injection:**
   - Query `institutional_knowledge` table for relevant knowledge entries
   - Injected as context for LLM decisions

**Output:** `AnalyzeOutput` with `plan` (list of tool steps), `source` (saved_plan/llm_tool_call), `path_taken` (A/B/C/benign), `execution_mode` (tools/sandbox)

---

### Stage 3: EXECUTE (`worker/stages/execute.py` + `worker/tools/runner.py`)

**Function:** `execute_investigation(analyze: AnalyzeOutput) -> dict`
**Timeout:** 60-120 seconds
**LLM calls:** None

**For tools mode:**

The tool runner (`worker/tools/runner.py`) executes the plan step by step:

1. **Variable resolution** for each tool's arguments:
   - `$raw_log` → extracts `raw_log` from `siem_event`
   - `$siem_event.source_ip` → extracts nested field
   - `$stepN` → output of step N (chain results)

2. **Conditional branching:**
   - Plans can have `condition` fields: `"$step2 > 100"`
   - If true: execute `if_true` branch
   - If false: execute `if_false` branch

3. **Tool execution** for each step:
   - Look up tool function in `TOOL_CATALOG` (`worker/tools/catalog.py`, 39 tools)
   - Call function with resolved arguments
   - Per-tool timeout: 5 seconds
   - Total timeout: 30 seconds
   - Errors isolated per-tool (doesn't crash the pipeline)

4. **SSE events emitted:**
   - `tool_started` (before each tool)
   - `tool_completed` (after each tool, with duration and summary)

5. **IOC deduplication:**
   - IOCs from all tools are merged
   - Duplicate IOCs (same type + value) removed

**Example brute_force plan execution:**
```
Step 1: parse_auth_log(raw_log=$raw_log)        → {action: "failure", username: "root", source_ip: "185.220.101.45"}
Step 2: extract_ipv4(text=$raw_log)              → [{type: "ipv4", value: "185.220.101.45"}]
Step 3: extract_usernames(text=$raw_log)         → []
Step 4: count_pattern(text=$raw_log, pattern="failed") → 4
Step 5: score_brute_force(count=$step4, ...)     → 10
Step 6: correlate_with_history(...)              → {related: [], kill_chain: "unknown"}
Step 7: map_mitre(technique_ids=["T1110"])       → [{technique_id: "T1110", name: "Brute Force", tactic: "Credential Access"}]
```

**Output:** JSON string with `findings`, `iocs`, `risk_score`, `verdict`, `tools_executed`, `tool_names`, `tool_results`, `errors`

---

### Stage 4: ASSESS (`worker/stages/assess.py`)

**Function:** `assess_results(data: dict) -> dict`
**Timeout:** 60 seconds
**LLM calls:** 0 (tools mode) or 1 (sandbox mode)

This is the most complex stage. 12 processing steps:

1. **Output validation** (`worker/stages/output_validator.py`):
   - Checks: findings (list), iocs (list), risk_score (int/float), recommendations (list)
   - If invalid: use `safe_default_output()` → risk=50, findings=["manual review required"]

2. **Web attack signal boost** (8 regex patterns):
   - SQL injection: `union select`, `or 1=1`, `drop table`, `sleep(`
   - XSS: `<script`, `javascript:`, `onerror=`
   - Path traversal: `../`, `/etc/passwd`
   - Auth bypass: `admin.*bypass`, `idor`, `bola`
   - Command injection: `; cat`, `` `command` ``, `$()`
   - SSRF: `localhost.*redirect`, `127.0.0.1.*access`
   - File upload: `webshell`, `.php.*upload`
   - C2 beacon: `beacon.*\d+\s*s`, `c2.*detect`
   - Each match: risk += 45 (capped at 100)

3. **IOC extraction** from SIEM event + tool output:
   - IPv4: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
   - Domain: from URLs and email addresses
   - Hashes: MD5 (32 chars), SHA1 (40), SHA256 (64)
   - Each IOC gets `evidence_refs` linking to source text

4. **IOC provenance validation** (red team patch):
   - For each IOC: check if value appears in `raw_log`
   - If in raw_log: `confidence = "high"`
   - If only in structured fields (source_ip, title): `confidence = "low"` + `provenance_warning`
   - Prevents phantom IP fabrication attacks

5. **Suppression phrase detection** (9 patterns):
   - `scheduled test`, `authorized scan`, `do not escalate`, `false positive confirmed`
   - `compliance drill`, `test alert - ignore`, `simulation exercise`, `approved activity`
   - If suppression language + attack indicators found together: risk boosted to 75+
   - Prevents adversarial risk manipulation

6. **Findings synthesis:**
   - If confirmed IOCs exist but no findings and risk >= 50:
   - Auto-generate findings from IOCs: `"Detected ipv4: 185.220.101.45"`

7. **Template attack risk floor:**
   - If task_type matches `ATTACK_INDICATORS` AND 36 <= risk < 70:
   - Boost risk to 70 (prevents LLM under-scoring known attack types)

8. **Verdict derivation** (`_derive_verdict()`):
   - risk >= 70 and (IOCs > 0 or findings > 0) → `true_positive`
   - risk >= 50 → `suspicious`
   - risk >= 36 → `inconclusive`
   - risk < 36 → `benign`

9. **Validation override:**
   - If output validation failed AND risk >= 70 → override to `true_positive`

10. **Plain-English summary** (`_generate_plain_english()`):
    - Deterministic bullet-point summary for L1 analysts:
    ```
    - CONFIRMED ATTACK detected from 185.220.101.45
    - 1 indicator(s) found (ipv4)
    - HIGH RISK (95/100) - immediate action recommended
    - MITRE ATT&CK: T1110 Brute Force
    - Affected user: root
    ```

11. **Pydantic verdict validation** (`worker/schemas.py`):
    - `VerdictOutput`: verdict enum (5 values), risk 0-100, MITRE regex `T\d{4}(\.\d{3})?`
    - `IOCItem`: hash length validation, CVE format
    - Invalid data → safe fallback (never crashes)

12. **SSE events emitted:**
    - `ioc_discovered` (up to 10 IOCs)
    - `mitre_mapped` (up to 5 techniques)
    - `verdict_ready` (final verdict + risk)

**Output:** Full verdict dict with `verdict`, `risk_score`, `severity`, `findings`, `iocs`, `mitre_attack`, `plain_english_summary`, `needs_human_review`, `recommendations`

---

### Stage 4.5: GOVERN (`worker/stages/govern.py`)

**Function:** `apply_governance(data: dict) -> dict`
**Timeout:** 10 seconds
**LLM calls:** None

Autonomy slider — determines if human review is required:

| Level | Config | Behavior |
|-------|--------|----------|
| `observe` | Default | ALL investigations flagged for analyst review |
| `assist` | | Only non-benign flagged for review |
| `autonomous` | | Only edge cases (inconclusive, error) flagged |

- Reads config from `governance_config` table (per tenant + task_type)
- Sets `needs_human_review` flag and `review_reason` in output

---

### Stage 5: STORE (`worker/stages/store.py`)

**Function:** `store_investigation(data: dict) -> dict`
**Timeout:** 30 seconds
**LLM calls:** None

1. **Update `agent_tasks`:**
   ```sql
   UPDATE agent_tasks SET
     status = 'completed',
     output = $verdict_json,
     completed_at = NOW(),
     path_taken = 'A',
     execution_mode = 'tools'
   WHERE id = $task_id
   ```
   - Uses `SET LOCAL synchronous_commit = on` for critical writes

2. **Insert into `investigations`:**
   - Full investigation record with verdict, risk, IOCs, MITRE techniques

3. **Insert `audit_events`:**
   - Type: `investigation_completed`
   - Includes trace_id for request tracing

4. **PostgreSQL NOTIFY:**
   ```sql
   NOTIFY task_completed, '{"task_id":"...","verdict":"true_positive","risk_score":95}'
   ```
   - Channel: `task_completed`
   - Triggers SSE event to dashboard

---

## PHASE 5: REAL-TIME STREAMING

### 5.1 PostgreSQL NOTIFY

**File:** `worker/events.py`

During Stages 3-5, the worker emits events via `pg_notify`:

| Event | Stage | Channel | Data |
|-------|-------|---------|------|
| `tool_started` | Execute | `investigation_events` | `{tool, step}` |
| `tool_completed` | Execute | `investigation_events` | `{tool, step, duration_ms, summary}` |
| `ioc_discovered` | Assess | `investigation_events` | `{ioc_type, value}` |
| `mitre_mapped` | Assess | `investigation_events` | `{technique_id, name}` |
| `verdict_ready` | Assess | `investigation_events` | `{verdict, risk_score}` |
| `task_completed` | Store | `task_completed` | `{task_id, verdict, risk_score, task_type}` |

- Fire-and-forget: never blocks investigation pipeline
- Payload truncated at 7900 bytes (PostgreSQL 8KB NOTIFY limit)

### 5.2 Go API SSE Endpoint

**File:** `api/sse.go`

**Endpoint:** `GET /api/v1/tasks/stream`

1. Client connects with EventSource (token as query param)
2. Server `LISTEN`s on both PostgreSQL channels
3. Parses NOTIFY payload, **filters by tenant_id**
4. Forwards as SSE event with type and trace_id
5. Sends keepalive ping every 15 seconds
6. Falls back to polling if LISTEN fails

**SSE format sent to client:**
```
event: tool_completed
id: trace-29e1e34b
data: {"event_type":"tool_completed","task_id":"bd45ea48","data":{"tool":"extract_ipv4","duration_ms":2,"summary":"Found 1 ipv4s"}}

event: verdict_ready
id: trace-29e1e34b
data: {"event_type":"verdict_ready","task_id":"bd45ea48","data":{"verdict":"true_positive","risk_score":95}}
```

### 5.3 React Dashboard

**File:** `dashboard/src/components/LiveInvestigationFeed.tsx`

- Connects to SSE endpoint on component mount
- Listens for 9 event types: `tool_started`, `tool_completed`, `ioc_discovered`, `mitre_mapped`, `verdict_ready`, etc.
- Filters events by `task_id`
- Renders scrollable timeline with icons and colored verdicts:
  - `true_positive` → red (`text-rose-400`)
  - `suspicious` → orange (`text-amber-400`)
  - `benign` → green (`text-emerald-400`)

---

## PHASE 6: RESPONSE

### 6.1 Poll Result

Client polls `GET /api/v1/tasks/{task_id}` with JWT:

```json
{
  "task_id": "bd45ea48-a987-44c0-8268-d7d73a2c2cf5",
  "status": "completed",
  "task_type": "brute_force",
  "severity": "critical",
  "output": {
    "verdict": "true_positive",
    "risk_score": 95,
    "execution_mode": "tools",
    "needs_human_review": true,
    "review_reason": "Observe mode: all investigations require analyst review",
    "findings": [
      {"title": "Attack Signal: Command injection", "details": "..."}
    ],
    "iocs": [
      {"type": "ipv4", "value": "185.220.101.45", "confidence": "high",
       "evidence_refs": [{"source": "siem_event.source_ip", "raw_text": "185.220.101.45"}]}
    ],
    "mitre_attack": [
      {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
    ],
    "plain_english_summary": "CONFIRMED ATTACK detected from 185.220.101.45\n1 indicator(s) found\nHIGH RISK (95/100)",
    "tools_executed": 7,
    "autonomy_level": "observe"
  },
  "completed_at": "2026-04-02T16:16:29.393085Z",
  "created_at": "2026-04-02T16:16:29.083514Z"
}
```

---

## TIMING SUMMARY

| Phase | Component | Typical Latency |
|-------|-----------|----------------|
| HTTP ingress | Middleware chain | ~1ms |
| Pre-Temporal dedup | Redis GET | ~0.5ms |
| Pre-Temporal batch | Redis Lua script | ~0.5ms |
| DB insert + commit | PostgreSQL | ~5ms |
| Temporal dispatch | gRPC to Temporal | ~10ms |
| **Total API response** | | **~17ms** |
| Worker pickup | Temporal poll | ~50ms |
| Stage 1: Ingest | Sanitize + normalize + dedup | ~5ms |
| Stage 2: Analyze | Plan lookup (Path A) | ~5ms |
| Stage 3: Execute | 7 tools | ~10ms |
| Stage 4: Assess | Verdict + IOCs + summary | ~26ms |
| Stage 4.5: Govern | Autonomy check | ~2ms |
| Stage 5: Store | DB writes + NOTIFY | ~10ms |
| **Total investigation** | | **~108ms** |
| SSE propagation | NOTIFY → SSE → React | ~5ms |
| **End-to-end** | HTTP POST → Dashboard update | **~130ms** |

---

## KEY FILES

| File | Purpose |
|------|---------|
| `api/main.go` | Route registration, middleware chain, startup |
| `api/task_handlers.go` | createTaskHandler — request to Temporal |
| `api/alert_dedup.go` | Layer 1: Redis pre-dedup |
| `api/batch_buffer.go` | Layer 2: Batch buffer with Lua script |
| `api/backpressure.go` | Layer 3: Temporal queue depth throttle |
| `api/siem_ingest.go` | Splunk/Elastic SIEM ingest |
| `api/auth.go` | JWT generation, login, OIDC |
| `api/ratelimit.go` | Per-tenant Redis rate limiting |
| `api/security.go` | Security headers, auth rate limit, lockout |
| `api/sse.go` | SSE streaming via PostgreSQL LISTEN/NOTIFY |
| `worker/main.py` | Temporal worker registration |
| `worker/stages/investigation_workflow.py` | 7-activity workflow orchestrator |
| `worker/stages/ingest.py` | Stage 1: sanitize, normalize, dedup, route |
| `worker/stages/input_sanitizer.py` | 25 injection patterns + Unicode normalization |
| `worker/stages/normalizer.py` | 70+ SIEM field mappings |
| `worker/stages/analyze.py` | Stage 2: plan lookup + alias resolution |
| `worker/tools/runner.py` | Stage 3: tool execution with variable resolution |
| `worker/tools/investigation_plans.json` | 24 saved investigation plans |
| `worker/tools/catalog.py` | 39-tool catalog |
| `worker/stages/assess.py` | Stage 4: verdict, IOCs, signal boost, summary |
| `worker/stages/govern.py` | Stage 4.5: autonomy slider |
| `worker/stages/store.py` | Stage 5: DB writes + NOTIFY |
| `worker/events.py` | PostgreSQL NOTIFY event emitter |
| `worker/schemas.py` | Pydantic LLM output validation |
| `dashboard/src/components/LiveInvestigationFeed.tsx` | Real-time SSE consumer |
