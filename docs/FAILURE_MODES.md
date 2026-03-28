# ZOVARK Investigation Failure Modes

> **Last updated: v1.5.1 (2026-03-24).** Race condition (#1) FIXED in v1.2.0. LLM model names (#5) FIXED in v1.5.0.

Contextual error logging and recovery for the `/v1/investigate` pipeline.

## Failure Mode Matrix

| # | Failure Mode | Audit Event Type | Context Logged | Recovery Action |
|---|-------------|-----------------|----------------|-----------------|
| 1 | Model Latency/Timeout | `model_timeout` | alert_id, model_provider, latency_ms, tier_attempted | Failover to local vLLM (Ollama qwen2.5:7b). Record `usage_records` with `fallback=true`. |
| 2 | Telemetry Access Denied | `telemetry_access_denied` | mssp_id, client_token_expiry, siem_endpoint, http_status | Webhook alert to MSSP for credential rotation. Set `agent_tasks.status='blocked_credentials'`. |
| 3 | Schema Validation Error | `schema_validation_error` | raw_llm_output_snippet (500 chars), target_schema, alert_type, validation_errors[] | Re-route to reasoning tier (Claude Sonnet) for JSON repair. Max 1 retry. |
| 4 | PostgreSQL Lock (5s) | `postgres_lock` | query_type, active_transactions, table_name, lock_wait_ms | Cancel query. Revert to `investigation_memory`. Return HTTP 503 with `Retry-After: 5`. |

## Shared Context Fields

Every failure event captures:

| Field | Source | Description |
|-------|--------|-------------|
| `mssp_id` | JWT `tenant_id` | The MSSP tenant that owns the investigation |
| `alert_id` | `agent_tasks.id` | The task/alert being investigated |
| `alert_priority` | `input.severity` or `normalized_event.severity` | Alert severity (critical/high/medium/low) |

## Implementation Details

### Mode 1: Model Latency/Timeout

**Trigger:** Temporal workflow start exceeds context deadline, or LiteLLM returns timeout.

**Detection points:**
- `api/handlers.go` `createTaskHandler` -- workflow start timeout
- `api/siem.go` `autoInvestigateAlert` -- workflow start timeout
- `worker/activities.py` `generate_code` -- LiteLLM call timeout (existing retry logic)

**Recovery flow:**
1. Log `FailureContext` to `audit_events`
2. Insert `usage_records` entry with `metadata.fallback=true`, `model_name=ollama/qwen2.5:7b`
3. Caller retries with Ollama or Tier-2 model

**Audit event metadata:**
```json
{
  "failure_mode": "model_timeout",
  "mssp_id": "tenant-uuid",
  "alert_id": "task-uuid",
  "alert_priority": "high",
  "details": {
    "model_provider": "groq",
    "latency_ms": 15230,
    "tier_attempted": "zovark-fast"
  },
  "recovery_action": "failover_to_local_vllm",
  "recovered": true
}
```

### Mode 2: Telemetry Access Denied

**Trigger:** SIEM log source credentials expired (`connection_config.token_expiry` in the past) or HTTP 401/403 from SIEM endpoint.

**Detection points:**
- `api/siem.go` `investigateAlertHandler` -- credential expiry check before investigation
- `api/siem.go` `webhookAlertHandler` -- HMAC validation failure (existing)

**Recovery flow:**
1. Log `FailureContext` to `audit_events`
2. Set `agent_tasks.status = 'blocked_credentials'` with descriptive error message
3. Dispatch `credential_rotation_required` webhook via `DispatchWebhook()` to all active endpoints
4. MSSP receives webhook, rotates credentials, investigation can be retried

**Audit event metadata:**
```json
{
  "failure_mode": "telemetry_access_denied",
  "mssp_id": "tenant-uuid",
  "alert_id": "task-uuid",
  "alert_priority": "critical",
  "details": {
    "siem_endpoint": "log_source:source-uuid",
    "http_status": 401,
    "client_token_expiry": "2026-03-01T00:00:00Z"
  },
  "recovery_action": "webhook_credential_rotation_alert",
  "recovered": false
}
```

### Mode 3: Schema Validation Error

**Trigger:** LLM output fails JSON parsing or doesn't match the expected investigation schema.

**Detection points:**
- `worker/activities.py` `generate_code` -- JSON decode failure
- `worker/activities.py` `extract_entities` -- entity schema mismatch
- `worker/activities.py` `check_guardrails` -- guardrail score parse failure

**Recovery flow:**
1. Log `FailureContext` to `audit_events` with first 500 chars of raw output
2. Worker re-routes to reasoning tier (`zovark-reasoning` / Claude Sonnet) with JSON repair prompt
3. Max 1 retry -- if repair fails, investigation fails with full context in `agent_tasks.error_message`

**Audit event metadata:**
```json
{
  "failure_mode": "schema_validation_error",
  "mssp_id": "tenant-uuid",
  "alert_id": "task-uuid",
  "alert_priority": "medium",
  "details": {
    "raw_llm_output_snippet": "{ \"verdict\": true_positive, ...",
    "target_schema": "investigation_result",
    "alert_type": "brute_force",
    "validation_errors": ["invalid JSON at position 23", "missing required field: risk_score"]
  },
  "recovery_action": "reroute_reasoning_tier_json_repair",
  "recovered": false
}
```

### Mode 4: PostgreSQL Lock (5s limit)

**Trigger:** Any database query in the investigation path exceeds the 5-second context timeout.

**Detection points:**
- `api/handlers.go` `createTaskHandler` -- task INSERT
- `api/siem.go` `investigateAlertHandler` -- alert SELECT
- `api/siem.go` `autoInvestigateAlert` -- task INSERT

**Recovery flow:**
1. Query cancelled automatically by context deadline
2. Log `FailureContext` with `pg_stat_activity` count of active transactions
3. If HTTP context available: return `503 Service Unavailable` with `Retry-After: 5` header
4. If background context (auto-investigate): log only, return error to caller

**HTTP response:**
```json
{
  "error": "Database contention detected. Please retry.",
  "failure_mode": "postgres_lock",
  "retry_after": 5,
  "alert_id": "task-uuid"
}
```

## Database Changes (Migration 020)

| Change | Table | Description |
|--------|-------|-------------|
| New status value | `agent_tasks` | `blocked_credentials` added to status CHECK |
| New event types | `audit_events` | `model_timeout`, `telemetry_access_denied`, `schema_validation_error`, `postgres_lock` |
| Partial index | `audit_events` | `idx_audit_events_failure_modes` on failure event types |
| Partial index | `agent_tasks` | `idx_agent_tasks_blocked` WHERE status='blocked_credentials' |

## Source Files

| File | Changes |
|------|---------|
| `api/error_context.go` | New -- FailureContext struct, 4 handler functions, helper utilities |
| `api/handlers.go` | Wrapped `createTaskHandler` with 5s DB timeout + workflow timeout detection |
| `api/siem.go` | Wrapped `investigateAlertHandler` with credential check + DB timeout; wrapped `autoInvestigateAlert` with DB/workflow timeout |
| `migrations/020_failure_context.sql` | CHECK constraint updates + partial indexes |

## Querying Failure Events

```sql
-- Recent failures by mode
SELECT event_type, count(*), max(created_at)
FROM audit_events
WHERE event_type IN ('model_timeout', 'telemetry_access_denied', 'schema_validation_error', 'postgres_lock')
GROUP BY event_type;

-- Blocked investigations awaiting credential rotation
SELECT id, tenant_id, error_message, created_at
FROM agent_tasks
WHERE status = 'blocked_credentials'
ORDER BY created_at DESC;

-- Fallback usage records
SELECT tenant_id, task_id, model_name, metadata->>'original_provider' as original, created_at
FROM usage_records
WHERE metadata->>'fallback' = 'true'
ORDER BY created_at DESC;
```
