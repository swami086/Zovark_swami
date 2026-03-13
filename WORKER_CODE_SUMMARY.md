# HYDRA Worker Code Summary

Exhaustive documentation of every Python file in `worker/`, including all classes, functions, Temporal activities/workflows, and key imports.

---

## Table of Contents

1. [worker/main.py](#workermainpy)
2. [worker/workflows.py](#workerworkflowspy)
3. [worker/activities.py](#workeractivitiespy)
4. [worker/model_config.py](#workermodel_configpy)
5. [worker/prompt_registry.py](#workerprompt_registrypy)
6. [worker/llm_logger.py](#workerllm_loggerpy)
7. [worker/cost_calculator.py](#workercost_calculatorpy)
8. [worker/investigation_memory.py](#workerinvestigation_memorypy)
9. [worker/investigation_cache.py](#workerinvestigation_cachepy)
10. [worker/entity_graph.py](#workerentity_graphpy)
11. [worker/entity_normalize.py](#workerentity_normalizepy)
12. [worker/context_manager.py](#workercontext_managerpy)
13. [worker/prompt_init.py](#workerprompt_initpy)
14. [worker/rate_limiter.py](#workerrate_limiterpy)
15. [worker/redis_client.py](#workerredis_clientpy)
16. [worker/logger.py](#workerloggerpy)
17. [worker/validation/__init__.py](#workervalidation__init__py)
18. [worker/validation/dry_run.py](#workervalidationdry_runpy)
19. [worker/prompts/__init__.py](#workerprompts__init__py)
20. [worker/prompts/entity_extraction.py](#workerpromptsentity_extractionpy)
21. [worker/prompts/investigation_prompt.py](#workerpromptsinvestigation_promptpy)
22. [worker/security/__init__.py](#workersecurity__init__py)
23. [worker/security/injection_detector.py](#workersecurityinjection_detectorpy)
24. [worker/security/prompt_sanitizer.py](#workersecurityprompt_sanitizerpy)
25. [worker/intelligence/__init__.py](#workerintelligence__init__py)
26. [worker/intelligence/blast_radius.py](#workerintelligenceblast_radiuspy)
27. [worker/intelligence/fp_analyzer.py](#workerintelligencefp_analyzerpy)
28. [worker/intelligence/cross_tenant.py](#workerintelligencecross_tenantpy)
29. [worker/intelligence/cross_tenant_workflow.py](#workerintelligencecross_tenant_workflowpy)
30. [worker/reporting/__init__.py](#workerreporting__init__py)
31. [worker/reporting/incident_report.py](#workerreportingincident_reportpy)
32. [worker/skills/__init__.py](#workerskills__init__py)
33. [worker/skills/deobfuscation.py](#workerskillsdeobfuscationpy)
34. [worker/bootstrap/__init__.py](#workerbootstrap__init__py)
35. [worker/bootstrap/activities.py](#workerbootstrapactivitiespy)
36. [worker/bootstrap/workflow.py](#workerbootstrapworkflowpy)
37. [worker/bootstrap/cisa_parser.py](#workerbootstrapcisa_parserpy)
38. [worker/bootstrap/mitre_parser.py](#workerbootstrapmitre_parserpy)
39. [worker/detection/__init__.py](#workerdetection__init__py)
40. [worker/detection/pattern_miner.py](#workerdetectionpattern_minerpy)
41. [worker/detection/sigma_generator.py](#workerdetectionsigma_generatorpy)
42. [worker/detection/rule_validator.py](#workerdetectionrule_validatorpy)
43. [worker/detection/workflow.py](#workerdetectionworkflowpy)
44. [worker/finetuning/__init__.py](#workerfinetuning__init__py)
45. [worker/finetuning/data_export.py](#workerfinetuningdata_exportpy)
46. [worker/finetuning/evaluator.py](#workerfinetuningevaluatorpy)
47. [worker/finetuning/workflow.py](#workerfinetuningworkflowpy)
48. [worker/models/__init__.py](#workermodels__init__py)
49. [worker/models/registry.py](#workermodelsregistrypy)
50. [worker/response/__init__.py](#workerresponse__init__py)
51. [worker/response/actions.py](#workerresponseactionspy)
52. [worker/response/workflow.py](#workerresponseworkflowpy)
53. [worker/sre/__init__.py](#workersre__init__py)
54. [worker/sre/monitor.py](#workersremonitorpy)
55. [worker/sre/diagnose.py](#workersrediagnosepy)
56. [worker/sre/patcher.py](#workersrepatcherpy)
57. [worker/sre/tester.py](#workersretesterpy)
58. [worker/sre/applier.py](#workersreapplierpy)
59. [worker/sre/workflow.py](#workersreworkflowpy)

---

## worker/main.py

**Purpose:** Entry point for the Temporal worker process. Connects to Temporal, registers all 7 workflows and 58 activities, and starts the worker.

**Key Imports:**
- `temporalio.client.Client`, `temporalio.worker.Worker`
- All workflows: `ExecuteTaskWorkflow`, `BootstrapCorpusWorkflow`, `CrossTenantRefreshWorkflow`, `DetectionGenerationWorkflow`, `ResponsePlaybookWorkflow`, `FineTuningPipelineWorkflow`, `SelfHealingWorkflow`
- All 58 activity functions from `activities`, `entity_graph`, `bootstrap.activities`, `intelligence.*`, `skills.deobfuscation`, `reporting.incident_report`, `detection.*`, `response.workflow`, `finetuning.workflow`, `sre.*`
- `prompt_init.init_prompts`, `logger`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_generate_worker_id()` | none | `str` | Generates a worker identity string from hostname, PID, and 4 random chars |
| `main()` | none | `None` (async) | Initializes prompts, connects to Temporal (with 10 retries), creates Worker with all workflows/activities on `hydra-tasks` queue, and runs it |

**Module-Level:**
- `WORKER_ID`: Read from env `WORKER_ID` or auto-generated via `_generate_worker_id()`

---

## worker/workflows.py

**Purpose:** Defines the main `ExecuteTaskWorkflow` -- the core SOC investigation workflow orchestrating code generation, sandbox execution, entity extraction, blast radius, FP analysis, reporting, and SOAR response.

**Key Imports:**
- `temporalio.workflow`
- All activity functions from `activities`, `entity_graph`, `intelligence.*`, `reporting.incident_report`, `response.workflow`, `security.injection_detector`, `security.prompt_sanitizer`

**Constants:**
- `MAX_STEPS = 3` -- Maximum investigation steps per workflow

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_verdict_from_severity(severity: str)` | severity | `str` | Maps severity level (critical/high/medium/low/informational) to investigation verdict (true_positive/suspicious/benign/inconclusive) |

**Temporal Workflows:**

### `@workflow.defn class ExecuteTaskWorkflow`

**Signals:**
- `approval_decision(data: dict)` -- Receives human approval/rejection decisions

**Methods:**

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `run(task_request: dict)` | task_request | `dict` | Main workflow entry. Fetches task, acquires lease, runs investigation, releases lease. Returns `{status, steps}` |
| `_run_investigation(task_id, tenant_id, task_type, task_data)` | 4 args | `dict` | Core pipeline: audit logging, skill RAG retrieval, injection detection, untrusted data wrapping, memory enrichment (Step 0), multi-step code gen/validate/execute loop, entity graph, cross-tenant intel, blast radius, FP analysis, incident report, SOAR auto-trigger |
| `_fail_task(task_id, tenant_id, reason, tokens_input, tokens_output, exec_ms)` | 6 args | `dict` | Helper to mark task as failed, log audit, return `{status: "failed"}` |

**Pipeline Steps (within `_run_investigation`):**
1. Audit logging (investigation_started)
2. Skill RAG retrieval (keyword + vector similarity)
3. Injection detection (regex-based)
4. Untrusted data wrapping (randomized delimiters)
5. Memory enrichment (Step 0, exact + semantic matching)
6. Multi-step loop (up to 3 steps):
   - Code generation (template or LLM)
   - AST validation
   - Dry-run validation gate (with retry)
   - Approval gate (if required)
   - Sandbox execution
   - Follow-up check
7. Post-loop: severity derivation, entity extraction, investigation embedding, entity graph write, cross-tenant intelligence, blast radius, FP analysis, incident report, SOAR playbook auto-trigger

---

## worker/activities.py

**Purpose:** Defines all core Temporal activities for the investigation workflow -- task fetching, code generation, sandbox execution, audit logging, usage recording, approval management, skill retrieval, memory operations, and validation.

**Key Imports:**
- `temporalio.activity`, `httpx`, `psycopg2`, `subprocess`, `re`, `json`
- `llm_logger.log_llm_call`, `prompt_registry.get_version`, `model_config.get_tier_config`
- `validation.dry_run.DryRunValidator`
- `sandbox.ast_prefilter.is_safe_python_code`

**Helper Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_get_worker_id()` | none | `str or None` | Lazy import of WORKER_ID from main module |
| `get_db_connection()` | none | `psycopg2.connection` | Creates PostgreSQL connection from DATABASE_URL env var |
| `_sync_commit(cur)` | cursor | `None` | Enables synchronous commit for critical writes |
| `_extract_iocs_from_input(task_input: dict)` | task_input | `list` | Quick regex extraction of IPs, domains, SHA256/MD5 hashes from alert input |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `fetch_task(task_id: str)` | task_id | `dict` | Queries agent_tasks table by ID, returns task data with id, tenant_id, task_type, input, status |
| `generate_code(task_data: dict)` | task_data | `dict{code, usage, execution_ms}` | Calls LiteLLM to generate Python investigation code. Supports file upload (real log data) and mock data modes. Post-processes code to replace `requests`, `input()`, `open()` with safe alternatives. Injects MockRequests shim. |
| `validate_code(code: str)` | code | `dict{is_safe, reason}` | Runs AST-based security validation via `is_safe_python_code()` |
| `execute_code(code: str)` | code | `dict{status, stdout, stderr, execution_ms}` | Executes code in Docker sandbox with seccomp, network isolation, read-only FS, 512MB memory, 0.5 CPU, 64 PID limit, 60s timeout |
| `update_task_status(task_update: dict)` | task_update | `None` | Updates agent_tasks with status, output, error_message, tokens, execution_ms, severity, worker_id |
| `log_audit(audit_data: dict)` | audit_data | `None` | Inserts into agent_audit_log table |
| `log_audit_event(event_data: dict)` | event_data | `None` | Inserts structured event into audit_events table |
| `record_usage(usage_data: dict)` | usage_data | `None` | Inserts into usage_records table (LLM/skill execution tracking) |
| `save_investigation_step(step_data: dict)` | step_data | `None` | Upserts into investigation_steps table (prompt, code, output, tokens, execution mode) |
| `check_followup_needed(check_data: dict)` | check_data | `dict{needed, prompt}` | Parses JSON output for `follow_up_needed` and `follow_up_prompt` fields. Guards against empty/duplicate prompts |
| `generate_followup_code(task_data: dict)` | task_data | `dict{code, usage, execution_ms}` | Generates follow-up investigation code with previous step context. Same post-processing as generate_code |
| `check_requires_approval(check_data: dict)` | check_data | `dict{required, reason, risk_level}` | Determines if step needs human approval. Rules: incident_response always, risk_score >= 80, dangerous code patterns (file write, os.remove, subprocess) |
| `create_approval_request(request_data: dict)` | request_data | `str (approval_id)` | Inserts into approval_requests table |
| `update_approval_request(update_data: dict)` | update_data | `None` | Updates approval_requests with status, decided_by, comment |
| `retrieve_skill(task_type: str, prompt: str)` | task_type, prompt | `dict or None` | Retrieves investigation skill via keyword matching (threat_types, keywords) then falls back to pgvector similarity search. Requires code_template IS NOT NULL. Increments times_used |
| `fill_skill_parameters(data: dict)` | data | `dict{filled_parameters, execution_ms, input_tokens, output_tokens}` | Uses LLM to extract parameter values from user prompt for skill template. Falls back to defaults on error |
| `render_skill_template(data: dict)` | data | `str` | Renders skill code template by replacing `{{param}}` placeholders with extracted values |
| `check_rate_limit_activity(data: dict)` | data | `bool` | Acquires lease-based rate limit. Reads max_concurrent from tenants table. Returns True if under limit |
| `decrement_active_activity(data: dict)` | data | `None` | Releases the lease for a task |
| `heartbeat_lease_activity(data: dict)` | data | `None` | Extends lease TTL during long-running activities |
| `validate_generated_code(code: str)` | code | `dict{passed, output, reason}` | Dry-run validation gate using DryRunValidator (5s timeout) |
| `enrich_alert_with_memory(task_input: dict)` | task_input | `dict{exact_matches, similar_entities, related_investigations}` | Step 0: Extracts IOCs from input, queries InvestigationMemory for exact + semantic matches |
| `write_investigation_memory(memory_data: dict)` | memory_data | `None` | Synthesizes investigation into 2-3 sentence memory via LLM, embeds it, stores in investigation_memory table. Fire-and-forget |

---

## worker/model_config.py

**Purpose:** 3-tier model routing configuration for LLM calls (fast/standard/reasoning). Maps activities to model tiers.

**Key Imports:** `os`

**Constants:**
- `MODEL_TIERS`: Dict with 3 tiers -- fast (hydra-fast, 1024 tokens, 0.1 temp), standard (hydra-standard, 4096 tokens, 0.3 temp), reasoning (hydra-reasoning, 4096 tokens, 0.2 temp)
- `ACTIVITY_TIER_MAP`: Maps 12 activity names to tiers (e.g., extract_entities -> fast, generate_code -> standard, analyze_false_positive -> reasoning)

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `get_tier_config(activity_name: str)` | activity_name | `dict` | Returns model config dict (model, max_tokens, temperature, tier). Supports env override via HYDRA_LLM_MODEL |
| `get_model_for_activity(activity_name: str)` | activity_name | `str` | Returns model ID for activity |
| `get_temperature_for_activity(activity_name: str)` | activity_name | `float` | Returns temperature for activity |
| `get_max_tokens_for_activity(activity_name: str)` | activity_name | `int` | Returns max_tokens for activity |

---

## worker/prompt_registry.py

**Purpose:** SHA256-based version tracking for all LLM prompts. Each prompt gets a version hash (first 12 chars of SHA256) that changes when prompt text changes.

**Key Imports:** `hashlib`

**Module-Level:** `_REGISTRY = {}` (global dict: name -> {content, version, description})

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_compute_version(content: str)` | content | `str` | Computes SHA256[:12] version hash |
| `register_prompt(name: str, content: str, description: str)` | 3 args | `str` | Registers prompt, returns version hash |
| `get_prompt(name: str)` | name | `dict` | Returns {content, version, description} or empty dict |
| `get_version(name: str)` | name | `str` | Returns version hash or empty string |
| `get_all_prompts()` | none | `dict` | Returns {name: {version, description}} for all prompts |
| `prompt_count()` | none | `int` | Number of registered prompts |

---

## worker/llm_logger.py

**Purpose:** Non-blocking logging of all LLM API calls to llm_call_log table. Fire-and-forget: errors printed but never raised.

**Key Imports:** `os`, `psycopg2`, `cost_calculator.calculate_cost`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `estimate_cost(input_tokens: int, output_tokens: int, model: str)` | 3 args | `float` | Estimates USD cost using per-model rates |
| `log_llm_call(activity_name, model_tier, model_id, prompt_name, prompt_version, input_tokens, output_tokens, latency_ms, status, error_message, temperature, max_tokens, tenant_id, task_id)` | 14 kwargs | `None` | Inserts LLM call record into llm_call_log table. Fire-and-forget |

---

## worker/cost_calculator.py

**Purpose:** Per-model cost calculation for LLM calls. Defines per-1K-token rates for all model variants.

**Constants:**
- `COST_PER_1K`: Dict mapping 15+ model IDs to input/output cost per 1K tokens. Covers fast (Groq), standard (Gemini Pro), reasoning (Claude Sonnet), fallbacks, air-gap (Ollama, free), and legacy.
- `DEFAULT_RATE`: `{input: 0.01, output: 0.03}` for unknown models

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `calculate_cost(model, input_tokens, output_tokens)` | 3 args | `float` | Calculates USD cost: `(input * rate_in + output * rate_out) / 1000` |

---

## worker/investigation_memory.py

**Purpose:** Pre-investigation enrichment with two-pass matching: exact value match first, then pgvector semantic search. Wired into ExecuteTaskWorkflow as Step 0.

**Key Imports:** `logging`, `os`, `httpx`, `psycopg2`

**Constants:**
- `SIMILARITY_THRESHOLDS`: Per-entity-type cosine distance thresholds (ip: 0.15, domain: 0.20, file_hash: 0.10, user: 0.25, etc.)
- `SIMILARITY_OVERRIDE`: Float from env `HYDRA_SIMILARITY_THRESHOLD`

**Classes:**

### `class InvestigationMemory`

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `__init__(db_url)` | db_url (optional) | - | Initializes DB URL, LiteLLM URL, API key, embedding URL |
| `enrich_alert(alert_entities)` | list of {type, value} | `dict{exact_matches, similar_entities, related_investigations}` | Two-pass enrichment: exact match, then semantic search. Skips semantic if exact found |
| `_exact_match(cur, entity_type, entity_value)` | 3 args | `dict or None` | Joins entities -> entity_observations -> investigations for exact value match |
| `_semantic_search(cur, entity_type, entity_value)` | 3 args | `dict or None` | pgvector cosine distance search with per-type threshold |
| `_get_embedding(text)` | text | `list or None` | Gets embedding via LiteLLM embed endpoint |
| `_get_threshold(entity_type)` | entity_type | `float` | Returns similarity threshold (env override or per-type default) |

---

## worker/investigation_cache.py

**Purpose:** Skip re-investigation for identical indicators. SHA-256 hash of normalized, sorted indicators maps to cached verdict + report. 24-hour TTL.

**Key Imports:** `hashlib`, `json`, `os`, `re`, `psycopg2`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_normalize_indicators(indicators)` | indicators | `list[str]` | Extracts and normalizes IOCs (IPs, domains, SHA256, MD5) from input. Returns sorted list of `type:value` strings |
| `compute_cache_key(task_input)` | task_input | `str or None` | Computes SHA-256 cache key from normalized indicators |
| `check_cache(task_input)` | task_input | `dict or None` | Checks investigation_cache table for unexpired entry. Returns cache_hit, verdict, risk_score, etc. |
| `store_cache(task_input, investigation_id, task_id, verdict, risk_score, confidence, entity_count, summary, ttl_hours)` | 9 args | `None` | Upserts into investigation_cache with TTL. Fire-and-forget |

---

## worker/entity_graph.py

**Purpose:** Entity graph Temporal activities: extract entities via LLM, write to DB (entities, observations, edges), embed investigations with pgvector.

**Key Imports:**
- `temporalio.activity`, `httpx`, `psycopg2`, `re`, `json`, `time`
- `entity_normalize.normalize_entity`, `entity_normalize.compute_entity_hash`
- `prompts.entity_extraction.ENTITY_EXTRACTION_SYSTEM_PROMPT`, `build_entity_extraction_prompt`
- `llm_logger.log_llm_call`, `prompt_registry.get_version`, `model_config.get_tier_config`

**Constants:**
- `VALID_ENTITY_TYPES`: frozenset of 8 types (ip, domain, file_hash, url, user, device, process, email)
- `VALID_ROLES`: frozenset of 8 roles (source, destination, attacker, victim, indicator, artifact, infrastructure, target)
- `VALID_EDGE_TYPES`: frozenset of 11 edge types (communicates_with, resolved_to, logged_into, etc.)
- Regex patterns: `_IP_RE`, `_DOMAIN_RE`, `_HASH_RE`, `_EMAIL_RE`
- `_DOMAIN_SKIP`: frozenset of false-positive domains

**Helper Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_regex_extract_entities(text: str)` | text | `list[dict]` | Fallback regex extraction when LLM output is malformed |
| `_validate_entity(e: dict)` | entity dict | `bool` | Validates entity has required fields and valid type |
| `_validate_edge(edge: dict)` | edge dict | `bool` | Validates edge has valid source, target, and edge_type |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `extract_entities(data: dict)` | {investigation_output, task_type, tenant_id, task_id} | `dict{entities, edges, usage_tokens, execution_ms}` | Calls LiteLLM with entity extraction prompt, parses JSON, validates entities/edges. Falls back to regex on error |
| `write_entity_graph(data: dict)` | {tenant_id, task_id, investigation_id, entities, edges, confidence_source} | `dict{entities_upserted, edges_upserted, observations_created, entity_hashes}` | Normalizes entities, computes hashes, batch upserts to entities/entity_observations/entity_edges tables. Flags injection_detected investigations |
| `embed_investigation(data: dict)` | {tenant_id, task_id, summary, verdict, risk_score, confidence, ...} | `dict{investigation_id, embedding_dim, execution_ms}` | Creates investigations row with embedding via TEI endpoint. Stores verdict, risk_score, confidence, attack_techniques |

**Utility Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `search_similar_investigations(tenant_id, embedding, limit)` | 3 args | `list[dict]` | pgvector cosine similarity search on investigations table. Excludes injection-flagged results |

---

## worker/entity_normalize.py

**Purpose:** Entity normalization and hashing for cross-tenant deduplication. Pure stdlib Python.

**Key Imports:** `hashlib`, `ipaddress`, `re`, `urllib.parse`

**Constants:**
- `_TRACKING_PARAMS`: frozenset of URL tracking parameters to strip (utm_*, fbclid, gclid, etc.)

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `normalize_ip(value: str)` | value | `str` | Normalizes IP: defang, strip port, strip leading zeros, handle IPv6 |
| `normalize_domain(value: str)` | value | `str` | Normalizes domain: lowercase, strip www., trailing dot, defang |
| `normalize_file_hash(value: str)` | value | `str` | Normalizes hash: lowercase, strip type prefix, validate hex + length |
| `normalize_url(value: str)` | value | `str` | Normalizes URL: lowercase scheme+host, remove tracking params, defang |
| `normalize_email(value: str)` | value | `str` | Normalizes email: lowercase, strip plus-addressing |
| `normalize_entity(entity_type: str, value: str)` | 2 args | `str` | Dispatches to type-specific normalizer, falls back to strip+lower |
| `compute_entity_hash(entity_type: str, normalized_value: str)` | 2 args | `str` | SHA256 hash of `{type}:{normalized_value}` for cross-tenant dedup |

---

## worker/context_manager.py

**Purpose:** Model-aware truncation for LLM inputs. Implements head/tail truncation preserving start and end of content.

**Key Imports:** `model_config.get_max_tokens_for_activity`

**Constants:**
- `CHARS_PER_TOKEN = 4`
- `SYSTEM_PROMPT_RESERVE = 300`
- `RESPONSE_RESERVE = 200`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `estimate_tokens(text: str)` | text | `int` | Rough token count (chars / 4) |
| `truncate_for_model(text: str, activity_name: str, max_input_chars: int)` | 3 args | `str` | Head/tail truncation (70/30 split) to fit model context window |
| `truncate_log_data(log_data: str, max_chars: int)` | 2 args | `str` | Truncates log data with head/tail preservation (default 50000 chars) |

---

## worker/prompt_init.py

**Purpose:** Registers all 16 LLM prompts at worker startup. Called from main.py before worker starts.

**Key Imports:** `prompt_registry.register_prompt`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `init_prompts()` | none | `None` | Registers 16 prompts: code_generation_with_logs, code_generation_mock, code_generation_followup, parameter_extraction, entity_extraction, incident_report, fp_analysis, synthetic_investigation, investigation_memory, sigma_generation, investigation_with_memory, brute_force_investigation_v1, malware_triage_v1, phishing_analysis_v1, lateral_movement_v1, c2_communication_v1 |

---

## worker/rate_limiter.py

**Purpose:** Lease-based rate limiter using atomic Redis Lua scripts. Each task acquires a lease (SET NX + EX), heartbeats extend TTL, release deletes the key. Fails open if Redis is down.

**Key Imports:** `os`, `redis`, `logger`

**Constants:**
- Lua scripts: `_ACQUIRE_SCRIPT` (atomic acquire + count check), `_RELEASE_SCRIPT` (atomic release)
- Lease key pattern: `tenant:{tenant_id}:lease:{task_id}`
- TTL: 60 seconds (heartbeat every 20s)

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_get_redis()` | none | `redis.Redis` | Singleton Redis connection from REDIS_URL env |
| `_ensure_scripts(r)` | redis instance | `None` | Registers Lua scripts (cached by SHA) |
| `_lease_key(tenant_id, task_id)` | 2 args | `str` | Builds lease key |
| `_active_set_key(tenant_id)` | tenant_id | `str` | Builds active set key |
| `acquire_lease(tenant_id, task_id, worker_id, max_concurrent, ttl)` | 5 args | `bool` | Atomically acquires lease if under concurrency limit. Fails open on Redis error |
| `release_lease(tenant_id, task_id)` | 2 args | `None` | Releases lease. Idempotent |
| `heartbeat_lease(tenant_id, task_id, ttl)` | 3 args | `None` | Extends lease TTL |
| `get_active_count(tenant_id)` | tenant_id | `int` | Returns number of active leases for tenant |

---

## worker/redis_client.py

**Purpose:** Legacy Redis client for simple INCR/DECR rate limiting (pre-lease era). Still used for backwards compatibility.

**Key Imports:** `os`, `redis`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_get_redis()` | none | `redis.Redis` | Singleton Redis connection |
| `get_active_count(tenant_id: str)` | tenant_id | `int` | Gets active count from `hydra:active:{tenant_id}` key |
| `increment_active(tenant_id: str)` | tenant_id | `int` | Increments active count with 1hr TTL |
| `decrement_active(tenant_id: str)` | tenant_id | `int` | Decrements active count, floors at 0 |
| `check_rate_limit(tenant_id: str, max_concurrent: int)` | 2 args | `bool` | Returns True if under limit (atomic incr + check) |

---

## worker/logger.py

**Purpose:** Structured JSON logging for HYDRA worker. Outputs to stderr.

**Key Imports:** `json`, `sys`, `time`, `os`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `log(level, message, **kwargs)` | level, message, kwargs | `None` | Outputs JSON log entry with ts, level, msg, worker, plus any kwargs |
| `info(msg, **kw)` | msg, kwargs | `None` | Log at info level |
| `warn(msg, **kw)` | msg, kwargs | `None` | Log at warn level |
| `error(msg, **kw)` | msg, kwargs | `None` | Log at error level |

---

## worker/validation/__init__.py

**Purpose:** Package init. Exports `DryRunValidator`.

---

## worker/validation/dry_run.py

**Purpose:** Dry-run validation gate for LLM-generated investigation code. Executes code in ultra-restricted sandbox (5s timeout) before committing to full investigation.

**Key Imports:** `asyncio`, `json`, `subprocess`, `tempfile`, `os`, `logging`

**Constants:**
- `REQUIRED_OUTPUT_KEYS = {'findings', 'confidence', 'entities', 'verdict'}`

**Classes:**

### `class DryRunValidator`

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `__init__(timeout: int, memory_limit: str)` | timeout=5, memory_limit="128m" | - | Configures timeout and memory limit |
| `validate(code: str)` | code | `dict{passed, output, reason}` | Runs static checks, dynamic dry-run in subprocess, validates output schema (required keys, confidence type, verdict enum) |
| `_static_checks(code: str)` | code | `dict{passed, output, reason}` | Checks for infinite loops, network calls, syntax errors |
| `_execute_with_timeout(code: str)` | code | `dict` | Writes wrapped code to temp file, executes with subprocess, enforces 128MB memory limit via resource.setrlimit |
| `_indent_code(code: str, spaces: int)` | code, spaces | `str` | Indents code block for wrapping |

---

## worker/prompts/__init__.py

**Purpose:** Package init. Comment: "Prompt templates for HYDRA worker activities".

---

## worker/prompts/entity_extraction.py

**Purpose:** LLM prompt template for structured entity extraction from investigation output.

**Constants:**
- `ENTITY_EXTRACTION_SYSTEM_PROMPT`: System prompt defining JSON output schema for entities (type, value, role, context, mitre_technique) and edges (source, target, edge_type, mitre_technique)

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `build_entity_extraction_prompt(investigation_output: str, task_type: str, max_chars: int)` | 3 args | `str` | Builds user prompt, truncating investigation output to max_chars (default 3000 for Qwen 1.5B) |

---

## worker/prompts/investigation_prompt.py

**Purpose:** Investigation prompt template with memory context injection. JSON enforcement is in the prompt text (not via API response_format).

**Constants:**
- `INVESTIGATION_PROMPT_V1`: Template with placeholders for alert_type, source, timestamp, raw_data, memory_section. Requires JSON output with findings, confidence, entities, verdict, recommended_actions, reasoning.

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `build_investigation_prompt(alert, memory)` | alert dict, optional memory | `str` | Builds prompt with optional memory enrichment. Truncates raw_data to 2000 chars |
| `_format_memory(memory)` | memory dict | `str` | Formats exact matches and similar indicators into prompt context |

---

## worker/security/__init__.py

**Purpose:** Empty package init.

---

## worker/security/injection_detector.py

**Purpose:** Deterministic regex-based prompt injection detection. Pure regex, <1ms. Flags but does not strip payloads -- attempted AI subversion IS a threat signal.

**Key Imports:** `re`, `dataclasses.dataclass`

**Classes:**

### `@dataclass class InjectionScanResult`
- `is_suspicious: bool`
- `matched_patterns: list` (category strings)
- `confidence_source: str` ('clean', 'suspicious', 'injection_detected')
- `raw_matches: list` (dicts with pattern, category, match, position)

**Constants:**
- `_PATTERNS`: Dict of 4 categories with compiled regex patterns:
  - `role_override`: 5 patterns (ignore previous instructions, you are now, override instructions, etc.)
  - `token_injection`: 5 patterns (im_start, im_end, system, INST, SYS tags)
  - `verdict_manipulation`: 5 patterns (classify as false positive, mark as benign, risk_score=0, etc.)
  - `prompt_extraction`: 3 patterns (print your prompt, what are your instructions, repeat the above)

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `scan_for_injection(text: str)` | text | `InjectionScanResult` | Scans text against all patterns. confidence_source: clean (0 matches), suspicious (1 category), injection_detected (2+ categories) |

---

## worker/security/prompt_sanitizer.py

**Purpose:** Randomized prompt delimiters to wrap untrusted data, preventing prompt injection.

**Key Imports:** `uuid.uuid4`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `wrap_untrusted_data(data: str, data_type: str)` | data, data_type | `tuple(wrapped_data, system_instruction)` | Wraps data in `<UNTRUSTED_{TYPE}_{nonce}>` delimiters. Returns wrapped data + system instruction telling LLM to treat content as passive data only |

---

## worker/intelligence/__init__.py

**Purpose:** Empty package init.

---

## worker/intelligence/blast_radius.py

**Purpose:** Blast radius computation via recursive CTE on entity graph.

**Key Imports:** `os`, `psycopg2`, `temporalio.activity`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `compute_blast_radius(data: dict)` | {investigation_id, tenant_id, time_window_hours: 72, max_hops: 2} | `dict{investigation_id, affected_entities, affected_investigations, total_entities, max_threat_score, summary}` | Recursive CTE traverses entity graph from investigation's entities up to max_hops. Finds affected entities and related investigations sharing those entities |

---

## worker/intelligence/fp_analyzer.py

**Purpose:** False positive confidence analyzer. Combines similar investigation lookup (pgvector), entity overlap queries, cross-tenant boost, and LLM reasoning chain.

**Key Imports:** `os`, `json`, `httpx`, `psycopg2`, `temporalio.activity`, `security.prompt_sanitizer`, `llm_logger`, `prompt_registry`, `model_config`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `analyze_false_positive(data: dict)` | {investigation_id, tenant_id, summary, verdict, risk_score, entities, cross_tenant_hits} | `dict{confidence, verdict, reasoning, evidence, recommendation}` | 5-step process: (1) embed summary + find similar investigations, (2) query entity overlap, (3) compute base confidence from verdict agreement, (4) LLM reasoning chain with wrapped data, (5) update investigation confidence in DB |

---

## worker/intelligence/cross_tenant.py

**Purpose:** Cross-tenant entity resolution -- materialized view refresh, entity intelligence, threat scoring. Privacy-safe: never exposes other tenant data.

**Key Imports:** `os`, `datetime`, `psycopg2`, `temporalio.activity`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `refresh_cross_tenant_intel(data: dict)` | {} | `dict{entities_correlated, multi_tenant_entities}` | Refreshes cross_tenant_intel materialized view concurrently, updates entities.tenant_count |
| `get_entity_intelligence(data: dict)` | {entity_hash, tenant_id} | `dict{entity_hash, entity_type, global_threat_score, tenant_count, investigation_count, your_investigations, first_seen_globally, last_seen_globally, mitre_techniques}` | Privacy-safe cross-tenant intelligence. Queries cross_tenant_public view, returns only requesting tenant's investigations |
| `compute_threat_score(data: dict)` | {entity_id, tenant_id} | `dict{entity_id, threat_score, factors}` | Computes threat score from observations (base), cross-tenant count (bonus), verdict distribution, recency. Max 100. Updates entity in DB |

---

## worker/intelligence/cross_tenant_workflow.py

**Purpose:** Temporal workflow for refreshing cross-tenant materialized view and recomputing threat scores.

**Key Imports:** `temporalio.workflow`, `temporalio.activity`, `psycopg2`, `intelligence.cross_tenant`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_list_multi_tenant_entities(data: dict)` | {} | `list[str]` | Lists entity IDs that appear across multiple tenants (joins entities with cross_tenant_intel) |

**Temporal Workflows:**

### `@workflow.defn class CrossTenantRefreshWorkflow`

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `run(params: dict)` | params | `dict` | (1) Refreshes materialized view, (2) Lists multi-tenant entities, (3) Recomputes threat score for each entity. Returns refresh stats + scores_updated count |

---

## worker/reporting/__init__.py

**Purpose:** Empty package init.

---

## worker/reporting/incident_report.py

**Purpose:** LLM-powered incident report generator with executive summary, technical timeline, remediation steps, and PDF output.

**Key Imports:** `os`, `io`, `json`, `time`, `httpx`, `psycopg2`, `temporalio.activity`, `security.prompt_sanitizer`, `llm_logger`, `prompt_registry`, `model_config`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_generate_pdf(report_title, investigation_id, verdict, risk_score, exec_summary, timeline, remediation)` | 7 args | `bytes or None` | Generates PDF using reportlab (A4 page, styled paragraphs). Returns None if reportlab not installed |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `generate_incident_report(data: dict)` | {investigation_id, tenant_id, summary, entities, edges, risk_score, verdict, attack_techniques, blast_radius} | `dict{report_id, markdown_length, pdf_size_bytes}` | Builds context, wraps as untrusted data, calls LLM for structured report, generates markdown + PDF, stores both in investigation_reports table |

---

## worker/skills/__init__.py

**Purpose:** Empty package init.

---

## worker/skills/deobfuscation.py

**Purpose:** Sandbox deobfuscation skill -- decodes base64, hex, PowerShell encoded, and URL-encoded payloads in an isolated Docker container.

**Key Imports:** `json`, `time`, `subprocess`, `temporalio.activity`

**Constants:**
- `DEOBFUSCATION_TEMPLATE`: Python script for trying 4 decoders (base64, hex, powershell_encoded, url_encoded)

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `run_deobfuscation(data: dict)` | {encoded_payload, tenant_id, task_id} | `dict{results, input_length, execution_ms}` | Runs deobfuscation script in Docker sandbox (network=none, read-only, seccomp, 512MB memory, 30s timeout). Returns decoded results for each successful decoder |

---

## worker/bootstrap/__init__.py

**Purpose:** Empty package init.

---

## worker/bootstrap/activities.py

**Purpose:** Bootstrap Temporal activities: load MITRE ATT&CK, load CISA KEV, generate synthetic investigations, extract entities.

**Key Imports:** `os`, `json`, `time`, `httpx`, `psycopg2`, `temporalio.activity`, `bootstrap.mitre_parser`, `bootstrap.cisa_parser`, `llm_logger`, `prompt_registry`, `model_config`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `load_mitre_techniques(data: dict)` | {stix_path, embedding_batch_size} | `dict{techniques_loaded, embeddings_created}` | Parses MITRE STIX bundle, batch upserts techniques into mitre_techniques table, embeds descriptions in batches via TEI |
| `load_cisa_kev(data: dict)` | {kev_path} | `dict{vulnerabilities_loaded}` | Parses CISA KEV JSON, inserts into bootstrap_corpus table |
| `generate_synthetic_investigation(data: dict)` | {source, source_id, title, description} | `dict{source_id, investigation_length, tokens_used}` | Uses LLM to generate synthetic SOC investigation for a MITRE technique or CISA CVE. Stores in bootstrap_corpus |
| `process_bootstrap_entity(data: dict)` | {source_id, source, tenant_id} | `dict{entities, edges, investigation_id}` | Extracts entities from bootstrap investigation, creates investigations row, writes entity graph, updates corpus status |
| `list_techniques(data: dict)` | {limit} | `list[dict]` | Lists MITRE techniques from DB for workflow processing |

---

## worker/bootstrap/workflow.py

**Purpose:** Bootstrap Corpus Temporal Workflow. Orchestrates MITRE + CISA loading, synthetic investigation generation, and entity extraction.

**Key Imports:** `temporalio.workflow`, bootstrap activities

**Temporal Workflows:**

### `@workflow.defn class BootstrapCorpusWorkflow`

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `run(params: dict)` | {tenant_id, max_techniques, batch_size, skip_mitre_load, skip_cisa_load} | `dict` | 4-step pipeline: (1) Load MITRE techniques, (2) Load CISA KEV, (3) Generate synthetic investigations for each technique, (4) Extract entities from each. Returns aggregate stats |

---

## worker/bootstrap/cisa_parser.py

**Purpose:** Parse CISA Known Exploited Vulnerabilities JSON file.

**Key Imports:** `json`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `parse_cisa_kev(filepath: str)` | filepath | `list[dict]` | Parses KEV JSON, returns list of {cve_id, vendor, product, name, description, date_added, due_date} |

---

## worker/bootstrap/mitre_parser.py

**Purpose:** Parse MITRE ATT&CK STIX bundle into technique dicts.

**Key Imports:** `json`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `parse_mitre_stix(filepath: str)` | filepath | `list[dict]` | Parses enterprise-attack.json, filters to attack-pattern objects (non-revoked, non-deprecated), extracts technique_id, name, description, tactics, platforms, data_sources, detection, url |

---

## worker/detection/__init__.py

**Purpose:** Empty package init.

---

## worker/detection/pattern_miner.py

**Purpose:** Discovers attack patterns from investigation corpus. Queries entity_observations + investigations for technique-entity correlations, creates detection_candidates.

**Key Imports:** `os`, `hashlib`, `psycopg2`, `temporalio.activity`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `mine_attack_patterns(data: dict)` | {min_investigations: 2} | `dict{candidates_found, candidates_created, candidates_updated}` | Finds technique-entity-role correlations and edge patterns across investigations. Groups by technique, computes pattern signature (SHA256), upserts into detection_candidates table |

---

## worker/detection/sigma_generator.py

**Purpose:** LLM-powered Sigma detection rule generation from attack pattern candidates.

**Key Imports:** `os`, `time`, `httpx`, `psycopg2`, `temporalio.activity`, `model_config`, `prompt_registry`, `llm_logger`

**Constants:**
- `SIGMA_SYSTEM_PROMPT`: System prompt for Sigma rule generation (YAML format, required fields, no tenant-specific data)

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `generate_sigma_rule(data: dict)` | {candidate_id, technique_id, pattern_description, entity_types, edge_patterns} | `dict{candidate_id, sigma_yaml, valid, error}` | Fetches MITRE technique description + example summaries, calls LLM (reasoning tier), validates YAML structure, stores in detection_candidates |

---

## worker/detection/rule_validator.py

**Purpose:** Validates Sigma rules against YAML structure requirements and tests TP/FP rates against historical investigation corpus.

**Key Imports:** `os`, `json`, `psycopg2`, `temporalio.activity`, optional `yaml`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_validate_sigma_structure(sigma_yaml: str)` | sigma_yaml | `dict{valid, errors, parsed}` | Validates YAML structure: required fields (title, logsource, detection, level), logsource must have category/product, detection must have condition + selection |
| `_update_candidate(candidate_id, status, validation_result)` | 3 args | `None` | Updates detection_candidates with validation results |
| `_create_detection_rule(candidate_id, technique_id, sigma_yaml, tp_rate, fp_rate, investigations_matched)` | 6 args | `str or None` | Creates versioned detection rule in detection_rules table |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `validate_sigma_rule(data: dict)` | {candidate_id, technique_id, sigma_yaml} | `dict{candidate_id, valid, tp_rate, fp_rate, status, errors, investigations_matched, rule_id}` | Structure validation + corpus testing. Auto-approve if TP >= 80% and FP <= 10%. Creates detection_rule if approved |

---

## worker/detection/workflow.py

**Purpose:** Detection generation workflow orchestrating pattern mining, Sigma generation, and validation.

**Key Imports:** `temporalio.workflow`, `temporalio.activity`, `psycopg2`, detection activities

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_list_candidates_for_generation(data: dict)` | {} | `list[dict]` | Lists detection_candidates with status='candidate', ordered by investigation_count DESC, limit 50 |

**Temporal Workflows:**

### `@workflow.defn class DetectionGenerationWorkflow`

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `run(params: dict)` | {min_investigations} | `dict` | 3-step pipeline: (1) Mine attack patterns, (2) List candidates, (3) Generate + validate Sigma rules for each. Returns stats: candidates_found, candidates_created, rules_generated, rules_validated, rules_approved |

---

## worker/finetuning/__init__.py

**Purpose:** Package init. Docstring: "Fine-tuning data pipeline for HYDRA."

---

## worker/finetuning/data_export.py

**Purpose:** Converts investigations into fine-tuning JSONL format. Exports investigation steps as instruction/response pairs.

**Key Imports:** `json`, `os`, `psycopg2`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `export_training_data(min_quality_score: float, limit: int)` | 2 args | `list[dict]` | Queries investigation_steps joined with agent_tasks and investigations. Computes quality scores, filters by min_quality. Returns {instruction, response, metadata} dicts |
| `compute_quality_score(verdict, confidence, code, output, execution_ms)` | 5 args | `float` | Scores 0.0-1.0 based on: verdict clarity (0-0.3), confidence (0-0.25), code length heuristic (0-0.25), output presence (0-0.1), execution speed (0-0.1) |
| `write_jsonl(examples: list, output_path: str)` | 2 args | `str` | Writes examples to JSONL in OpenAI chat fine-tuning format (system/user/assistant messages) |

---

## worker/finetuning/evaluator.py

**Purpose:** Model evaluation framework. Runs benchmark prompts through a model and scores outputs against expected keywords.

**Key Imports:** `os`, `time`, `httpx`

**Constants:**
- `BENCHMARK_PROMPTS`: 5 benchmark scenarios (brute_force, c2, lateral_movement, phishing, ransomware) with expected keywords

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `evaluate_model(model_name: str)` | model_name | `dict` | Runs all 5 benchmarks, returns per-prompt and aggregate scores (average_score, total_tokens, total_latency_ms) |
| `score_output(output: str, expected_keywords: list)` | 2 args | `float` | Scores 0.0-1.0: keyword coverage (0-0.5), Python code indicators (0-0.2), reasonable length (0-0.15), structure indicators (0-0.15) |

---

## worker/finetuning/workflow.py

**Purpose:** Fine-tuning pipeline Temporal workflow + activities.

**Key Imports:** `json`, `os`, `time`, `temporalio.activity`, `temporalio.workflow`, `psycopg2`, `finetuning.data_export`, `finetuning.evaluator`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `export_finetuning_data(data: dict)` | {min_quality_score, limit, output_dir} | `dict{examples_count, output_path, min_quality_score}` | Exports training data to JSONL file |
| `score_training_quality(data: dict)` | {output_path} | `dict{count, avg_quality, min_quality, max_quality, task_type_distribution, verdict_distribution}` | Reads JSONL and computes aggregate quality statistics |
| `run_model_evaluation(data: dict)` | {model} | `dict` | Runs benchmark evaluation on specified model |
| `create_finetuning_job(data: dict)` | {job_id, config, examples_count, quality_stats} | `dict{job_id, status}` | Creates finetuning_jobs record in DB |
| `update_finetuning_job(data: dict)` | {job_id, status, evaluation_results} | `dict{job_id, status}` | Updates finetuning_jobs with status and eval results |

**Temporal Workflows:**

### `@workflow.defn class FineTuningPipelineWorkflow`

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `run(params: dict)` | {job_id, min_quality_score, limit, model} | `dict` | 5-step pipeline: (1) Export training data, (2) Score quality, (3) Create job record, (4) Run model evaluation, (5) Update job. Returns training_examples, quality_stats, evaluation summary |

---

## worker/models/__init__.py

**Purpose:** Package init. Docstring: "Model registry and routing for HYDRA."

---

## worker/models/registry.py

**Purpose:** Dynamic model selection and routing. Supports per-tenant overrides, per-task-type routing, A/B traffic splitting, default fallback.

**Key Imports:** `os`, `random`, `psycopg2`, `logger`

**Module-Level:** `_model_cache = {}`, `_cache_ts = 0` (refreshed every 60s)

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `refresh_model_cache()` | none | `None` | Reads model_registry table (active/testing/promoted models) into in-memory cache |
| `get_model_for_task(tenant_id, task_type)` | 2 args | `str` | Priority: (1) A/B test random split, (2) tenant-specific routing rule, (3) task-type routing rule, (4) default model, (5) env fallback |
| `_check_ab_test(tenant_id, task_type)` | 2 args | `str or None` | Queries model_ab_tests for running test, random assignment based on traffic_split |
| `promote_model(model_id: str)` | model_id | `bool` | Promotes model to default, deprecates current default. Refreshes cache |

---

## worker/response/__init__.py

**Purpose:** Empty package init.

---

## worker/response/actions.py

**Purpose:** 7 simulated SOAR response actions. All actions log-only by default; call webhooks if integration exists.

**Key Imports:** `os`, `httpx`, `psycopg2`

**Helper Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_get_webhook(tenant_id, action_type)` | 2 args | `dict or None` | Checks response_integrations table for enabled webhook |
| `_call_webhook(webhook, payload)` | 2 args | `dict` | POSTs to webhook URL with bearer/api_key auth |
| `get_action(action_type: str)` | action_type | `ResponseAction` | Returns action instance from registry |

**Classes:**

### `class ResponseAction` (base)
- `action_type = "unknown"`
- Methods: `validate(context) -> bool`, `execute(context) -> dict`, `rollback(context, execution_result) -> dict`

### 7 Action Subclasses:

| Class | action_type | validate requires | Description |
|-------|------------|-------------------|-------------|
| `BlockIP` | `block_ip` | `ip` | Block IP on firewall |
| `DisableUser` | `disable_user` | `username` | Disable user account |
| `IsolateEndpoint` | `isolate_endpoint` | `hostname` or `ip` | Network-isolate endpoint |
| `RotateCredentials` | `rotate_credentials` | `username` or `service` | Rotate credentials (no rollback) |
| `CreateTicket` | `create_ticket` | `title` | Create incident ticket (no rollback) |
| `SendNotification` | `send_notification` | `message` or `channel` | Send Slack/Teams notification (no rollback) |
| `QuarantineFile` | `quarantine_file` | `file_hash` or `file_path` | Quarantine malicious file |

**Constants:**
- `ACTION_REGISTRY`: Maps action_type strings to action classes

---

## worker/response/workflow.py

**Purpose:** Response playbook workflow with approval gates, sequential action execution, and rollback on failure.

**Key Imports:** `os`, `json`, `temporalio.workflow`, `temporalio.activity`, `psycopg2`, `response.actions`

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `load_playbook(data: dict)` | {playbook_id} | `dict` | Loads playbook from response_playbooks table |
| `create_response_execution(data: dict)` | {playbook_id, investigation_id, tenant_id, trigger_data, status} | `str (execution_id)` | Creates response_executions record |
| `update_response_execution(data: dict)` | {execution_id, status, actions_executed} | `None` | Updates execution status and actions |
| `execute_response_action(data: dict)` | {action_type, context} | `dict` | Executes a single response action via get_action() |
| `rollback_response_action(data: dict)` | {action_type, context, execution_result} | `dict` | Rolls back a single response action |
| `find_matching_playbooks(data: dict)` | {verdict, risk_score, tenant_id} | `list[dict]` | Finds enabled playbooks matching verdict and risk_score threshold |

**Temporal Workflows:**

### `@workflow.defn class ResponsePlaybookWorkflow`

**Signals:**
- `playbook_approval_decision(data: dict)` -- Receives approval/rejection

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `run(params: dict)` | {playbook_id, investigation_id, tenant_id, trigger_data} | `dict{status, execution_id, actions_executed, playbook_name}` | 6-step process: (1) Load playbook, (2) Create execution, (3) Approval gate (1hr timeout, signal-based), (4) Execute actions sequentially, (5) Rollback on failure (reverse order), (6) Update final status |

---

## worker/sre/__init__.py

**Purpose:** Empty package init.

---

## worker/sre/monitor.py

**Purpose:** SRE Monitor -- scans Temporal and agent_tasks DB for workflow/activity failures.

**Key Imports:** `os`, `datetime`, `temporalio.activity`, `psycopg2`, `temporalio.client.Client`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_extract_failure_info(workflow_info, events)` | 2 args | `list[dict]` | Extracts failure details from workflow history events (ACTIVITY_TASK_FAILED, WORKFLOW_EXECUTION_FAILED) |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `scan_for_failures(data: dict)` | {lookback_minutes: 30} | `dict{failures, count, lookback_minutes}` | Scans Temporal for failed workflows (via list_workflows + fetch_history) and agent_tasks DB for failed tasks. Deduplicates by error_message |

---

## worker/sre/diagnose.py

**Purpose:** SRE Diagnose -- classifies failure root cause with deterministic 4-category classifier and LLM fallback.

**Key Imports:** `os`, `re`, `time`, `glob`, `temporalio.activity`, `httpx`, `llm_logger`, `model_config`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `classify_error(error_message, stack_trace)` | 2 args | `dict or None` | Deterministic 4-category classifier: dependency_missing (ModuleNotFoundError), logic_bug (TypeError/KeyError/etc.), llm_malformed (JSONDecodeError), resource_exhaustion (OOMKilled/TimeoutError). Returns None for unknown |
| `read_activity_source(activity_name: str)` | activity_name | `dict{file_path, content}` | Scans worker/*.py files for `@activity.defn` matching the activity name. Searches 9 directories |
| `llm_diagnose(error_message, stack_trace, activity_name)` | 3 args | `dict` | LLM fallback: reads source context, calls reasoning model for JSON classification. Returns {category, root_cause, auto_fixable, suggested_fix} |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `diagnose_failure(data: dict)` | {error_message, stack_trace, activity_name, workflow_id} | `dict` | Tries deterministic classification first, falls back to LLM. Attaches original failure info |

---

## worker/sre/patcher.py

**Purpose:** SRE Patcher -- generates category-specific patches for diagnosed failures.

**Key Imports:** `os`, `re`, `time`, `temporalio.activity`, `psycopg2`, `httpx`, `llm_logger`, `model_config`

**Constants:**
- `KNOWN_FIXES`: Dict mapping module names to pip package names (yaml -> pyyaml, PIL -> pillow, etc.)
- `MAX_PATCHES_PER_HOUR = 5`

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_check_rate_limit()` | none | `bool` | Checks self_healing_events table for patches in last hour |
| `_patch_dependency_missing(diagnosis)` | diagnosis | `dict` | Generates pip install patch from KNOWN_FIXES |
| `_patch_logic_bug(diagnosis)` | diagnosis | `dict` | Uses LLM (reasoning tier) to generate minimal code fix. Reads source, sends to LLM, returns patched file content |
| `_patch_llm_malformed(diagnosis)` | diagnosis | `dict` | Injects `_sanitize_json_response()` helper function into source file |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `generate_patch(data: dict)` | {category, ...diagnosis fields} | `dict{type, ...}` | Routes to category-specific patcher. Types: pip_install, code_patch, no_patch. Rate-limited to 5/hour |

---

## worker/sre/tester.py

**Purpose:** SRE Tester -- sandbox-isolated patch verification before application.

**Key Imports:** `os`, `tempfile`, `subprocess`, `temporalio.activity`

**Constants:**
- `SAFE_PACKAGES`: Set of 17 allowlisted pip packages

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_test_pip_install(data)` | data | `dict{passed, reason, ...}` | Verifies package is in SAFE_PACKAGES allowlist |
| `_test_code_patch(data)` | data | `dict{passed, exit_code, stdout, stderr}` | Syntax check via compile(), then writes to temp file and runs basic import test in subprocess (30s timeout) |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `test_patch(data: dict)` | {type, ...} | `dict{passed, ...}` | Routes to type-specific tester (pip_install, code_patch, no_patch) |

---

## worker/sre/applier.py

**Purpose:** SRE Applier -- safely applies verified patches with backup, audit logging, and dry-run support.

**Key Imports:** `os`, `json`, `subprocess`, `datetime`, `temporalio.activity`, `psycopg2`

**Constants:**
- `PROTECTED_FILES`: Set of 3 files that must never be modified (/app/sandbox/ast_prefilter.py, seccomp_profile.json, kill_timer.py)
- `SAFE_PACKAGES`: Same 17 packages as tester

**Functions:**

| Function | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `_log_self_healing_event(event_data)` | event_data | `None` | Inserts into self_healing_events table |
| `_log_audit_event(event_type, metadata)` | 2 args | `None` | Inserts audit event for self-healing actions |
| `_apply_code_patch(data, dry_run)` | 2 args | `dict` | Creates file backup, writes patched content, logs events. Rejects paths outside /app/ and protected files |
| `_apply_pip_install(data, dry_run)` | 2 args | `dict` | Runs `pip install` for allowlisted packages |

**Temporal Activities:**

| Activity | Parameters | Return | Description |
|----------|-----------|--------|-------------|
| `apply_patch(data: dict)` | {type, dry_run: True, ...} | `dict{applied, ...}` | Routes to type-specific applier. Dry run by default -- logs but does not apply. Creates timestamped backups for code patches |

---

## worker/sre/workflow.py

**Purpose:** Self-Healing SRE Workflow -- orchestrates the full failure scan, diagnosis, patching, testing, and application pipeline.

**Key Imports:** `temporalio.workflow`, SRE activities

**Temporal Workflows:**

### `@workflow.defn class SelfHealingWorkflow`

| Method | Parameters | Return | Description |
|--------|-----------|--------|-------------|
| `run(params: dict)` | {lookback_minutes: 30, dry_run: True} | `dict{status, failures_found, healed, failed_to_heal, dry_run, details}` | 5-step loop per failure: (1) Scan for failures, (2) Diagnose each, (3) Generate patch (skip if not auto_fixable), (4) Test patch, (5) Apply patch (dry_run default). Returns aggregate stats with per-failure details |

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Total Python files** | 59 |
| **Temporal Workflows** | 7 (ExecuteTaskWorkflow, BootstrapCorpusWorkflow, CrossTenantRefreshWorkflow, DetectionGenerationWorkflow, ResponsePlaybookWorkflow, FineTuningPipelineWorkflow, SelfHealingWorkflow) |
| **Temporal Activities** | 58 |
| **Registered Prompts** | 16 |
| **Response Action Types** | 7 (block_ip, disable_user, isolate_endpoint, rotate_credentials, create_ticket, send_notification, quarantine_file) |
| **Model Tiers** | 3 (fast, standard, reasoning) |
| **Entity Types** | 8 (ip, domain, file_hash, url, user, device, process, email) |
| **Edge Types** | 11 (communicates_with, resolved_to, logged_into, executed, downloaded, contains, parent_of, accessed, sent_to, received_from, associated_with) |
| **Injection Detection Categories** | 4 (role_override, token_injection, verdict_manipulation, prompt_extraction) |
| **SRE Error Categories** | 4 (dependency_missing, logic_bug, llm_malformed, resource_exhaustion) |
