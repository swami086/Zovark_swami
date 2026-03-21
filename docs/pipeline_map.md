# HYDRA Investigation Pipeline — Activity Map

Every activity the workflow calls, in execution order.

## Legend
- **LLM**: Calls LLM via LiteLLM/llama-server
- **DB**: Database tables touched
- **Redis**: Uses Redis for caching/rate limiting

---

## Stage 1: INGEST (no LLM)

| Order | Activity | LLM | DB Tables | Purpose |
|-------|----------|-----|-----------|---------|
| 1 | `fetch_task` | No | `agent_tasks` SELECT | Load task from DB |
| 2 | `check_rate_limit_activity` | No | `tenants` SELECT | Lease-based rate limit (Redis) |
| 3 | `log_audit_event` | No | `audit_events` INSERT | Log investigation start |
| 4 | `check_exact_dedup_activity` | No | Redis `dedup:exact:*` | Exact hash dedup (<1ms) |
| 5 | `check_correlation_activity` | No | Redis `dedup:corr:*` | Correlation window (15min) |
| 6 | `check_semantic_dedup_activity` | No | `investigation_fingerprints` SELECT | pgvector similarity (0.85 threshold) |
| 7 | `register_dedup_activity` | No | Redis SET | Register alert in dedup layers |
| 8 | `retrieve_skill` | No | `agent_skills` SELECT | Skill template RAG retrieval |
| 9 | `enrich_alert_with_memory` | No | `investigation_memory` SELECT | Past investigation lookup |
| 10 | `mask_for_llm` | No | Redis (entity map) | PII masking (9 regex patterns) |

**Input**: task_id (from API)
**Output**: IngestOutput (task_data, skill_template, pii_masked_prompt)

---

## Stage 2: ANALYZE (LLM for code generation)

| Order | Activity | LLM | DB Tables | Purpose |
|-------|----------|-----|-----------|---------|
| 11a | `fill_skill_parameters` | **YES** | `usage_records` INSERT | Extract params from SIEM event |
| 11b | `render_skill_template` | No | — | Jinja2 template rendering |
| 12 | `generate_code` | **YES** | `usage_records` INSERT | Full LLM code generation |
| 13 | `generate_followup_code` | **YES** | `usage_records` INSERT | Follow-up step code gen |
| 14 | `preflight_validate_code` | No | — | AST syntax check + auto-fix |
| 15 | `validate_code` | No | — | AST security prefilter |

**Three paths** (mutually exclusive):
- **Template** (11a→11b): skill matched → LLM fills params → render template
- **LLM Gen** (12): no template → full code generation
- **Follow-up** (13): step 2+ → generate with previous context

**Input**: IngestOutput
**Output**: AnalyzeOutput (code, source, preflight_passed)

---

## Stage 3: EXECUTE (no LLM — except adversarial review)

| Order | Activity | LLM | DB Tables | Purpose |
|-------|----------|-----|-----------|---------|
| 16 | `validate_generated_code` | No | — | Docker dry-run validation |
| 17 | `review_code` (adversarial) | **YES** | — | Red-team LLM check (10s timeout) |
| 18 | `execute_code` | No | — | Docker sandbox execution |
| 19 | `save_investigation_step` | No | `investigation_steps` INSERT | Persist step for crash recovery |
| 20 | `record_usage` | No | `usage_records` INSERT | Token usage tracking |

**Retry loop** (max 2 retries on failure):
- Captures stderr → feeds back to `generate_code` → re-execute

**Input**: AnalyzeOutput
**Output**: ExecuteOutput (stdout, iocs, findings, risk_score)

---

## Stage 4: ASSESS (LLM for entity extraction + FP analysis)

| Order | Activity | LLM | DB Tables | Purpose |
|-------|----------|-----|-----------|---------|
| 21 | `extract_entities` | **YES** | `usage_records` INSERT | LLM entity extraction (regex fallback) |
| 22 | `embed_investigation` | No | `investigations` INSERT | Create investigation row + embedding |
| 23 | `write_entity_graph` | No | `entities`, `entity_observations`, `entity_edges` INSERT | Graph upsert |
| 24 | `get_entity_intelligence` | No | `cross_tenant_entity_view` SELECT | Cross-tenant lookup |
| 25 | `compute_blast_radius` | No | `entity_edges` SELECT (recursive CTE) | N-hop graph traversal |
| 26 | `analyze_false_positive` | **YES** | `investigations` SELECT | Confidence scoring + LLM reasoning |

**Input**: ExecuteOutput
**Output**: AssessOutput (verdict, risk_score, confidence, entities)

---

## Stage 5: STORE (no LLM)

| Order | Activity | LLM | DB Tables | Purpose |
|-------|----------|-----|-----------|---------|
| 27 | `update_task_status` | No | `agent_tasks` UPDATE | Mark completed/failed |
| 28 | `log_audit` / `log_audit_event` | No | `agent_audit_log`, `audit_events` INSERT | Audit trail |
| 29 | `write_investigation_memory` | **YES** | `investigation_memory` INSERT | LLM summarization for memory |
| 30 | `save_investigation_pattern` | No | `investigation_memory` INSERT | Pattern storage |
| 31 | `store_fingerprint_activity` | No | `investigation_fingerprints` INSERT | Semantic dedup fingerprint |
| 32 | `generate_incident_report` | No | `investigations` SELECT | Markdown + PDF report |
| 33 | `find_matching_playbooks` | No | `response_playbooks` SELECT | SOAR auto-trigger |
| 34 | `auto_trigger_playbooks` | No | `audit_events` INSERT | Log trigger events |
| 35 | `unmask_response` | No | Redis (entity map) | PII unmask |
| 36 | `decrement_active_activity` | No | Redis DECR | Release rate limit lease |

**Input**: AssessOutput
**Output**: StoreOutput (task_id, investigation_id, status)

---

## LLM Call Summary

| # | Activity | File | Timeout | Purpose |
|---|----------|------|---------|---------|
| 1 | `fill_skill_parameters` | `_legacy_activities.py:1043` | 30s | Extract skill params |
| 2 | `generate_code` | `_legacy_activities.py:179` | 900s | Generate Python script |
| 3 | `generate_followup_code` | `_legacy_activities.py:694` | 900s | Follow-up code gen |
| 4 | `review_code` | `security/adversarial_review.py:135` | 10s | Red-team code review |
| 5 | `extract_entities` | `entity_graph.py:117` | 120s | Entity extraction |
| 6 | `analyze_false_positive` | `intelligence/fp_analyzer.py:92` | 60s | FP confidence scoring |
| 7 | `write_investigation_memory` | `_legacy_activities.py:1277` | 30s | Memory summarization |

**Total: 7 LLM call sites across 4 files.**

---

## Database Tables (17 tables)

| Table | Operations | Stage |
|-------|------------|-------|
| `agent_tasks` | SELECT, UPDATE | 1, 5 |
| `agent_audit_log` | INSERT | 5 |
| `audit_events` | INSERT | 1, 5 |
| `agent_skills` | SELECT, UPDATE | 1 |
| `investigation_steps` | INSERT, UPSERT | 3 |
| `investigations` | INSERT, SELECT | 4 |
| `investigation_memory` | INSERT, SELECT | 1, 5 |
| `investigation_fingerprints` | INSERT, SELECT | 1, 5 |
| `entities` | INSERT, UPSERT | 4 |
| `entity_observations` | INSERT | 4 |
| `entity_edges` | INSERT, SELECT | 4 |
| `cross_tenant_entity_view` | SELECT | 4 |
| `approval_requests` | INSERT, UPDATE | 3 |
| `usage_records` | INSERT | 2, 3 |
| `tenants` | SELECT | 1 |
| `response_playbooks` | SELECT | 5 |
| `alert_fingerprints` | SELECT, INSERT | API layer |
