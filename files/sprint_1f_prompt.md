# HYDRA Sprint 1F — Observability + Enterprise Readiness
## Claude Code Prompt

---

You are building Sprint 1F for HYDRA, an AI-powered SOC investigation automation platform. This sprint adds monitoring, encrypted inter-service communication, and structured LLM output enforcement.

## Context

HYDRA's stack: Go API → Temporal → Python workers → LLM (Qwen 1.5B/7B via LiteLLM) → Docker sandbox → PostgreSQL 16 + pgvector. Sprint 1E hardened the sandbox and auth. Sprint 1G added entity graph schema. Sprint 1F makes the platform observable and enterprise-ready.

## Deliverables

### 1F-1: Prometheus + Grafana Stack

**Add to Docker Compose:**
- Prometheus container (port 9090) with scrape configs for all services
- Grafana container (port 3001) with pre-configured dashboards

**Metrics to expose:**

From Go API (add /metrics endpoint using `prometheus/client_golang`):
- `hydra_api_requests_total{method, path, status}` — counter
- `hydra_api_request_duration_seconds{method, path}` — histogram
- `hydra_api_active_connections` — gauge

From Python worker (add prometheus_client to requirements.txt, expose on a sidecar port like 9091):
- `hydra_investigations_total{skill_type, verdict, tenant}` — counter
- `hydra_investigation_duration_seconds{skill_type}` — histogram
- `hydra_llm_call_duration_seconds{model, call_type}` — histogram (call_type: code_gen, entity_extraction, embedding)
- `hydra_llm_tokens_total{model, direction}` — counter (direction: input/output)
- `hydra_sandbox_execution_duration_seconds` — histogram
- `hydra_sandbox_oom_kills_total` — counter
- `hydra_entity_graph_writes_total{table}` — counter
- `hydra_worker_active_tasks` — gauge

From PostgreSQL (use postgres_exporter):
- Connection count, transaction rate, replication lag, table sizes

From Redis (use redis_exporter):
- Memory usage, connected clients, key count

**Grafana dashboards (provision via JSON):**
1. HYDRA Overview: investigations/min, success rate, active workers, queue depth
2. LLM Performance: latency by model, token usage, error rate
3. Infrastructure: DB connections, Redis memory, container health

**Prometheus scrape config:**
```yaml
scrape_configs:
  - job_name: 'hydra-api'
    static_configs:
      - targets: ['api:8090']
  - job_name: 'hydra-worker'
    static_configs:
      - targets: ['worker:9091']
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

### 1F-2: Structured LLM Output Enforcement

Currently the LLM returns free-text that gets parsed. This causes inconsistent risk scores and malformed entity extraction.

**For investigation code generation:**
- Add `response_format: {"type": "json_object"}` to LiteLLM calls where the worker expects structured output
- Define JSON schemas for each output type (investigation findings, entity extraction, risk assessment)
- Add validation layer: after LLM response, validate against schema before proceeding
- On validation failure: retry once with error feedback in prompt, then fall back to regex extraction

**For entity extraction (Sprint 1G):**
- The entity extraction prompt in `worker/prompts/entity_extraction.py` already requests JSON
- Add explicit schema validation after LLM response using a simple JSON schema check
- Validate: entities have required fields (type, value, role), edges have required fields (source, target, edge_type)
- Log validation failures as metrics: `hydra_llm_schema_failures_total{call_type}`

**For risk score calibration:**
- Add post-processing: clamp risk_score to 0-100 integer
- Add confidence calibration: if model returns confidence > 0.95 on first-pass investigation, cap at 0.85 (uncalibrated models are overconfident)

### 1F-3: LLM Call Logging Pipeline

Every LLM call must be logged for future fine-tuning (Layer 5 of moat roadmap).

Create a `llm_call_log` table:
```sql
CREATE TABLE IF NOT EXISTS llm_call_log (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    investigation_id UUID,
    call_type VARCHAR(50) NOT NULL,  -- code_generation, entity_extraction, embedding, parameter_fill
    model_id VARCHAR(100) NOT NULL,
    model_version VARCHAR(100),
    prompt_version VARCHAR(50),
    input_tokens INTEGER,
    output_tokens INTEGER,
    latency_ms INTEGER,
    input_text TEXT,           -- full prompt sent to LLM
    output_text TEXT,          -- full response from LLM
    output_valid BOOLEAN,      -- did it pass schema validation?
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_llm_log_tenant ON llm_call_log(tenant_id);
CREATE INDEX idx_llm_log_type ON llm_call_log(call_type);
CREATE INDEX idx_llm_log_valid ON llm_call_log(output_valid);
CREATE INDEX idx_llm_log_created ON llm_call_log(created_at);
```

Add to init.sql and create migration `migrations/002_sprint1f_observability.sql`.

Wire logging into every LiteLLM call in activities.py and entity_graph.py. Log AFTER the call completes (non-blocking, fire-and-forget like entity graph writes).

## Important Constraints

- Prometheus/Grafana must work in Docker Compose AND be represented in K8s manifests
- Metrics endpoints must not require authentication (internal network only)
- LLM call logging must not add latency to the critical path (async/fire-and-forget)
- All new containers must be in the existing Docker network (hydra-internal)
- Air-gap compatible: no external metric endpoints, all local

## Definition of Done

- [ ] Prometheus scraping all services, Grafana dashboards accessible at localhost:3001
- [ ] At least 10 custom HYDRA metrics visible in Prometheus
- [ ] LLM structured output validation in place with retry + fallback
- [ ] Risk score clamping and confidence calibration active
- [ ] llm_call_log table populated after investigations run
- [ ] All existing tests still pass
- [ ] Git commit: "Sprint 1F: Observability + structured LLM output + call logging"
