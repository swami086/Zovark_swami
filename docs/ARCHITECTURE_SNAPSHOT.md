# HYDRA Architecture Snapshot — 2026-03-21

## Current State
- **Git HEAD:** `2f99e9c` refactor: delete legacy workflow — V2 is the only pipeline
- **Containers:** 8 running / 17 total (core stack, no monitoring profile)
- **Workflow:** `InvestigationWorkflowV2` (default)
- **FAST_FILL:** NOT SET (defaults to false — real LLM mode)
- **LLM:** `Qwen2.5-14B-Instruct-Q4_K_M.gguf` via llama-server on RTX 3050
- **Worker:** healthy (old ExecuteTaskWorkflow replay errors are from stale Temporal history — non-blocking)
- **Unit tests:** 15/15 pass in 0.62s

## V2 Pipeline Files
```
   88 worker/stages/__init__.py      (contracts)
  426 worker/stages/analyze.py       (Stage 2 — LLM code gen)
  147 worker/stages/assess.py        (Stage 4 — LLM verdict)
  193 worker/stages/execute.py       (Stage 3 — sandbox)
  211 worker/stages/ingest.py        (Stage 1 — dedup/PII/skill)
  105 worker/stages/investigation_workflow.py  (V2 workflow)
   18 worker/stages/register.py      (registration helper)
  204 worker/stages/store.py         (Stage 5 — DB writes)
 1392 total
```

## LLM Containment Verification
- **Stages 1,3,5:** CLEAN — no httpx, LITELLM_URL, or urlopen
- **Stages 2,4:** LLM calls at:
  - `analyze.py:39` LITELLM_URL config
  - `analyze.py:244` httpx call (template param fill)
  - `analyze.py:349` httpx call (full code gen)
  - `assess.py:24` LITELLM_URL config
  - `assess.py:69` httpx call (LLM summary)

## Activity Registrations
```
worker/stages/analyze.py:389:  @activity.defn  → analyze_alert
worker/stages/assess.py:105:   @activity.defn  → assess_results
worker/stages/execute.py:148:  @activity.defn  → execute_investigation
worker/stages/ingest.py:150:   @activity.defn  → ingest_alert
worker/stages/store.py:128:    @activity.defn  → store_investigation
```
Note: `fetch_task` in ingest.py is NOT decorated (legacy version is registered)

## Full Workflow Code
```python
@workflow.defn
class InvestigationWorkflowV2:
    @workflow.run
    async def run(self, task_data: dict) -> dict:
        info = workflow.info()
        task_id = info.workflow_id.replace("task-", "")

        full_task = await workflow.execute_activity(
            "fetch_task", task_id,
            start_to_close_timeout=timedelta(seconds=10))
        if not full_task:
            return {"status": "failed", "task_id": task_id, "error": "Task not found"}
        full_task["task_id"] = task_id

        # Stage 1: INGEST (30s)
        ingested = await workflow.execute_activity(
            ingest_alert, full_task, start_to_close_timeout=timedelta(seconds=30))
        if ingested.get("is_duplicate"):
            return {"status": "deduplicated", "task_id": ingested["task_id"]}

        # Stage 2: ANALYZE (5min)
        analyzed = await workflow.execute_activity(
            analyze_alert, ingested, start_to_close_timeout=timedelta(seconds=300))
        if not analyzed.get("code"):
            return {"status": "failed", "task_id": ingested["task_id"]}

        # Stage 3: EXECUTE (2min)
        executed = await workflow.execute_activity(
            execute_investigation, {"code": analyzed["code"], "task_type": ingested["task_type"]},
            start_to_close_timeout=timedelta(seconds=120))

        # Stage 4: ASSESS (1min)
        assessed = await workflow.execute_activity(
            assess_results, {**executed, "task_id": ingested["task_id"],
            "tenant_id": ingested["tenant_id"], "task_type": ingested["task_type"]},
            start_to_close_timeout=timedelta(seconds=60))

        # Stage 5: STORE (30s)
        stored = await workflow.execute_activity(
            store_investigation, {**assessed, **executed,
            "task_id": ingested["task_id"], "tenant_id": ingested["tenant_id"]},
            start_to_close_timeout=timedelta(seconds=30))
        return stored
```

## Contracts (Dataclasses)
```python
@dataclass IngestOutput:   task_id, tenant_id, task_type, siem_event, prompt, is_duplicate, skill_id, skill_template, skill_params
@dataclass AnalyzeOutput:  code, source ("template"|"llm"|"fast_fill"), skill_id, preflight_passed, tokens_in/out, generation_ms
@dataclass ExecuteOutput:  stdout, stderr, exit_code, status, iocs, findings, risk_score, recommendations, execution_ms
@dataclass AssessOutput:   verdict, risk_score, severity, confidence, fp_confidence, entities, recommendations, memory_summary
@dataclass StoreOutput:    task_id, status, investigation_id, entities_stored, memory_saved, pattern_saved
```

## Registration
```python
def get_v2_activities():
    return [ingest_alert, analyze_alert, execute_investigation, assess_results, store_investigation]

def get_v2_workflows():
    return [InvestigationWorkflowV2]
```

## API Routing
```
task_handlers.go:23: var workflowName = getWorkflowName()
task_handlers.go:26: func getWorkflowName() string { ... HYDRA_WORKFLOW_VERSION ... }
task_handlers.go:169: tc.ExecuteWorkflow(..., workflowName, req)     // POST /api/v1/tasks
task_handlers.go:528: tc.ExecuteWorkflow(..., workflowName, req)     // bulk create
task_handlers.go:843: tc.ExecuteWorkflow(..., workflowName, ...)     // SIEM investigate
siem.go:278:           tc.ExecuteWorkflow(..., workflowName, ...)     // webhook auto-investigate
```

## Worker main.py Imports
```python
from stages.register import get_v2_activities, get_v2_workflows
from activities import fetch_task, log_audit, log_audit_event, record_usage, update_task_status, ...
from entity_graph import extract_entities, write_entity_graph, embed_investigation
from workflows.hydra_workflows import ZeekIngestionWorkflow, DeepLogAnalysisWorkflow, ...
# + 15 non-investigation workflow imports (bootstrap, detection, response, SRE, etc.)
```

## Docker Compose Defaults
```yaml
api:
  HYDRA_WORKFLOW_VERSION=${HYDRA_WORKFLOW_VERSION:-InvestigationWorkflowV2}

worker:
  LITELLM_URL=${LITELLM_URL:-http://host.docker.internal:11434/v1/chat/completions}
  # HYDRA_FAST_FILL removed (set explicitly for stress tests only)
```

## Skill Templates in DB
```
brute-force-investigation    | active
c2-communication-hunt        | active
cloud-infrastructure-attack  | active
data-exfiltration-detection  | active
insider-threat-detection     | active
lateral-movement-detection   | active
network-beaconing            | active
phishing-investigation       | active
privilege-escalation-hunt    | active
ransomware-triage            | active
supply-chain-compromise      | active
(11 templates)
```

## Unit Test Results
```
15/15 passed in 0.62s

TestStage1Ingest:   3/3 (required fields, dedup disabled, siem_event preserved)
TestStage2Analyze:  3/3 (fast_fill code, valid Python, no LLM tokens)
TestStage3Execute:  4/4 (execution, JSON parse, forbidden imports, empty code)
TestStage4Assess:   3/3 (verdict, high risk, no IOCs = benign)
TestStage5Store:    1/1 (contract fields)
TestFullPipeline:   1/1 (all 5 stages in sequence)
```

## Files Changed Since Legacy (78fae01..HEAD)
```
 worker/_legacy_workflows.py             | 1559 deleted
 worker/activities/__init__.py           |   15 +-
 worker/main.py                          |   31 +-
 worker/stages/__init__.py               |   88 new
 worker/stages/analyze.py                |  426 new
 worker/stages/assess.py                 |  147 new
 worker/stages/execute.py                |  193 new
 worker/stages/ingest.py                 |  211 new
 worker/stages/investigation_workflow.py |  105 new
 worker/stages/register.py               |   18 new
 worker/stages/store.py                  |  204 new
 worker/workflows/__init__.py            |    4 +-
 12 files changed, 1413 insertions(+), 1588 deletions(-)
```

## End-to-End Data Flow
1. SIEM alert arrives → `POST /api/v1/tasks` (Go API on port 8090)
2. API starts Temporal workflow: `InvestigationWorkflowV2` (via `workflowName` env var)
3. Workflow extracts `task_id` from workflow ID, calls `fetch_task` (string name, from `_legacy_activities.py`)
4. **Stage 1 INGEST** (`ingest.py`): Redis exact dedup, PII masking, skill template retrieval — NO LLM
5. **Stage 2 ANALYZE** (`analyze.py`): 3 paths — FAST_FILL stub / template+LLM params / full LLM code gen — **1 LLM CALL**
6. **Stage 3 EXECUTE** (`execute.py`): AST prefilter + Docker sandbox (or subprocess in FAST_FILL) — NO LLM
7. **Stage 4 ASSESS** (`assess.py`): verdict derivation, optional LLM summary, FP confidence — **1 LLM CALL**
8. **Stage 5 STORE** (`store.py`): write to `agent_tasks` + `investigation_memory` + `investigations` — NO LLM
9. Task status updated to `completed`, API returns results

## Key Architecture Facts
- **llama-server:** `C:\Users\vinay\llama-cpp\llama-server.exe` (native Windows, NOT Docker)
- **Model:** `Qwen2.5-14B-Instruct-Q4_K_M.gguf` (8.4GB, base — DPO adapter also available)
- **LITELLM_URL:** `http://host.docker.internal:11434/v1/chat/completions` (bypasses LiteLLM container)
- **Redis password:** `<REDACTED — set via REDIS_PASSWORD env var>`
- **Admin credentials:** `<REDACTED — set via HYDRA_ADMIN_EMAIL env var>` / `<REDACTED — set via HYDRA_ADMIN_PASSWORD env var>`
- **API port:** `localhost:8090`
- **`investigations` table source constraint:** `production`, `bootstrap`, `synthetic` only
- **`investigation_memory` table name:** singular (NOT `investigation_memories`)
- **DPO adapter:** `models/hydra-dpo-adapter/` (48MB LoRA, trained on 33 pairs)
- **DPO GGUF:** `models/hydra-dpo-Q4_K_M.gguf` (8.4GB, not currently active)

## Performance Benchmarks
| Test | Completion | Avg Time | Notes |
|------|-----------|----------|-------|
| V2 + FAST_FILL (100) | 100/100 | <2s | No LLM, regex stubs |
| V2 + LLM (10) | 10/10 | 52s | Real Qwen2.5-14B on RTX 3050 |
| Legacy + LLM (100) | 61/100 | 368s | 24 timeouts, 13 auth errors |
| Legacy + LLM (7 pipeline) | 7/7 | 411s | Full prompt engineering |
