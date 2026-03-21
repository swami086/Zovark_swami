# HYDRA Investigation Pipeline — 5-Stage Architecture

## Overview

```
SIEM Alert → INGEST → ANALYZE → EXECUTE → ASSESS → STORE → Verdict
               │         │         │         │         │
             no LLM    LLM ①    no LLM    LLM ②    no LLM
```

The pipeline has exactly **2 LLM boundaries**:
1. **ANALYZE** — code generation (template fill or full gen)
2. **ASSESS** — entity extraction + false positive reasoning

Everything else is deterministic (DB queries, regex, sandbox, graph traversal).

---

## Stage 1: INGEST

**Purpose**: Validate, deduplicate, and prepare the alert for investigation.
**LLM calls**: None.
**Latency**: <500ms (Redis + DB lookups).

### Steps
1. **Fetch task** from `agent_tasks` table
2. **Rate limit** check (lease-based, Redis)
3. **3-stage dedup** pipeline:
   - Exact: SHA-256 hash of alert fields (Redis, <1ms)
   - Correlation: Same rule+IP+host within 15-min window (Redis, <5ms)
   - Semantic: pgvector cosine similarity, 0.85 threshold (~50ms)
4. **Skill retrieval**: Match `task_type` to `agent_skills.threat_types` (exact → prefix → keyword)
5. **Memory enrichment**: Search past investigations for similar entities
6. **PII masking**: 9 regex patterns, entity map stored in Redis

### Contract
```python
@dataclass
class IngestOutput:
    task_id: str
    tenant_id: str
    task_type: str
    siem_event: Dict
    prompt: str
    is_duplicate: bool
    skill_id: Optional[str]
    skill_template: Optional[str]
    skill_params: List[Dict]
    pii_masked: bool
```

### Key Decision
If `is_duplicate=True`, the pipeline stops here (status="deduplicated").

---

## Stage 2: ANALYZE

**Purpose**: Generate Python investigation code.
**LLM calls**: 1-2 (parameter filling + code generation).
**Latency**: 5ms (fast_fill) to 10 min (LLM on RTX 3050).

### Three Paths

| Path | When | LLM Calls | Latency |
|------|------|-----------|---------|
| **Fast Fill** | `HYDRA_FAST_FILL=true` | 0 | ~5ms |
| **Template** | Skill matched with `code_template` | 1 (param fill) | ~30s |
| **LLM Gen** | No template match | 1 (full code gen) | 5-10 min |

### Path A: Fast Fill (stress test mode)
- Generates regex-based IOC extraction stub
- No LLM, no template, no network calls
- Used for plumbing tests and load testing

### Path B: Template
1. `fill_skill_parameters` — LLM extracts params from SIEM event (30s timeout)
2. `render_skill_template` — Jinja2 renders code with params (no LLM)
3. `preflight_validate_code` — AST check + auto-fix (<100ms)

### Path C: LLM Generation
1. `generate_code` — Full LLM code generation (900s timeout)
   - System prompt: sandbox constraints, JSON output schema
   - User prompt: SIEM event (wrapped with randomized delimiters)
   - PromptAssembler v2 with IOC patterns and specialist personas
2. `preflight_validate_code` — AST check + auto-fix
3. `validate_code` — AST security prefilter (blocked imports)

### Contract
```python
@dataclass
class AnalyzeOutput:
    code: str
    source: Literal["template", "llm", "stub", "fast_fill"]
    skill_id: Optional[str]
    preflight_passed: bool
    tokens_in: int
    tokens_out: int
    generation_ms: int
```

### Key Constraint
**This is the ONLY stage that should contain LLM code generation calls.**
All code-gen LLM interactions are routed through `worker/stages/analyze.py`.

---

## Stage 3: EXECUTE

**Purpose**: Run generated code in hardened Docker sandbox.
**LLM calls**: 1 (adversarial review, 10s timeout, pass-through on failure).
**Latency**: 10-60s (Docker startup + script execution).

### Steps
1. **Adversarial review** — Red-team LLM checks for 10 sandbox escape patterns
   - LRU cached (1000 entries)
   - Pass-through on timeout (Docker sandbox is primary security)
2. **Docker sandbox execution**:
   - `--network=none` (no network)
   - `--read-only` filesystem (except `/tmp`)
   - `--cap-drop=ALL` (no capabilities)
   - `--user=65534` (nobody)
   - seccomp profile (syscall whitelist)
   - 60s kill timer
3. **Step persistence** — Save code + output for crash recovery

### Retry Loop (max 2 retries)
If sandbox execution fails:
1. Capture stderr (error message)
2. Feed error + broken code back to `generate_code` (LLM)
3. Re-validate and re-execute
4. Log: `CODE_RETRY attempt N: ErrorType → FIXED/still failed`

### Contract
```python
@dataclass
class ExecuteOutput:
    stdout: str
    stderr: str
    exit_code: int
    status: Literal["completed", "failed", "timeout"]
    iocs: List[Dict]
    findings: List[Dict]
    risk_score: int
    execution_ms: int
    retries_used: int
```

---

## Stage 4: ASSESS

**Purpose**: Enrich results with entity graph, cross-tenant intel, FP analysis.
**LLM calls**: 2 (entity extraction + FP reasoning).
**Latency**: 30s-5 min.

### Steps
1. **Entity extraction** — LLM extracts entities + relationships (regex fallback)
2. **Investigation embedding** — Create `investigations` row with pgvector embedding
3. **Entity graph write** — Upsert entities, observations, edges
4. **Cross-tenant intelligence** — Lookup entity across all tenants (materialized view)
5. **Blast radius** — Recursive CTE on entity_edges (N hops, time-windowed)
6. **False positive analysis** — pgvector similarity + entity overlap + LLM reasoning

### Verdict Derivation
```
risk_score >= 80  → critical
risk_score >= 60  → high
risk_score >= 40  → medium
risk_score >= 20  → low
else              → informational
```

### Contract
```python
@dataclass
class AssessOutput:
    verdict: Literal["true_positive", "suspicious", "benign", "inconclusive"]
    risk_score: int
    severity: str
    confidence: float
    false_positive_confidence: float
    entities: List[Dict]
    edges: List[Dict]
    blast_radius: Dict
    memory_summary: str
```

---

## Stage 5: STORE

**Purpose**: Persist results, trigger SOAR, clean up.
**LLM calls**: 1 (memory summarization, optional).
**Latency**: <5s.

### Steps
1. **Update task status** — `agent_tasks` SET status=completed
2. **Audit logging** — agent_audit_log + audit_events
3. **Investigation memory** — LLM summarizes for future RAG
4. **Pattern storage** — Save successful code + IOCs for enrichment
5. **Semantic fingerprint** — Store embedding for future dedup
6. **Incident report** — Generate markdown + PDF
7. **SOAR auto-trigger** — Match playbooks by verdict + risk score
8. **PII unmask** — Replace masked tokens with originals
9. **Rate limit release** — Decrement active lease counter

### Contract
```python
@dataclass
class StoreOutput:
    task_id: str
    status: Literal["completed", "failed"]
    investigation_id: Optional[str]
    entities_stored: int
    memory_saved: bool
    playbooks_triggered: List[str]
```

---

## FAST_FILL Mode

When `HYDRA_FAST_FILL=true`, the pipeline skips ALL LLM calls:

| Stage | Normal | FAST_FILL |
|-------|--------|-----------|
| INGEST | Same | Same |
| ANALYZE | LLM code gen | Regex stub |
| EXECUTE | Adversarial review + sandbox | Sandbox only |
| ASSESS | LLM entity extraction + FP | Skip entity extraction, skip FP |
| STORE | LLM memory summarization | Template summary |

**Purpose**: Plumbing stress tests (100+ investigations) without LLM bottleneck.
**Latency**: ~15-30s per investigation (vs 5-10 min with LLM).

---

## Architecture Principles

1. **LLM boundaries are explicit** — Only ANALYZE and ASSESS call the LLM
2. **Every LLM call has a fallback** — Regex, pass-through, or rules-based
3. **Retry is in the workflow, not the activity** — Activities are pure functions
4. **State is in the database** — Workflow can crash and resume from `investigation_steps`
5. **Security is defense-in-depth** — AST prefilter → adversarial review → Docker sandbox
6. **Dedup happens before LLM** — Saves compute on duplicate alerts
7. **Memory enriches future prompts** — Past investigations improve code quality
