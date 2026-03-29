# HYDRA Sprint 5 — Claude Code Execution Prompt
## CTO-Reviewed & Corrected — March 8, 2026

> **Copy this entire file into Claude Code.** Every error from the original Brainiac prompt has been fixed. 11 corrections applied — see ERRATA section at the end.

---

## PROJECT CONTEXT

```
Repo:     C:\Users\vinay\Desktop\HYDRA\hydra-mvp  (Windows host)
Branch:   master
Latest:   8efdb4f (Sprint 4A)
Stack:    Python worker (Temporal), Go API, PostgreSQL+pgvector, Redis, LiteLLM, Docker Compose
Host OS:  Windows — ALL Python runs inside Docker containers
Bash:     Use semicolons (;) not && for command chaining
```

**Critical existing infrastructure (DO NOT recreate — MODIFY):**
- `litellm_config.yaml` — already exists, currently routes all tiers to Gemini Flash via OpenRouter
- `docker-compose.yml` — already has LiteLLM service, 10 containers total
- `worker/model_config.py` — existing 3-tier model routing with `get_tier_config()`
- `worker/prompt_registry.py` — SHA256-based prompt versioning with `get_version()`
- `worker/llm_logger.py` — non-blocking LLM call logging with `log_llm_call()`
- `worker/activities.py` — core activities: `generate_code`, `execute_code`, etc.
- `worker/workflows.py` — `ExecuteTaskWorkflow` (main investigation pipeline)
- `worker/entity_graph.py` — entity extraction + graph writing
- `worker/entity_normalize.py` — IP/domain/hash normalization
- `worker/security/injection_detector.py` — 3-level injection classification
- `worker/prompts/entity_extraction.py` — existing prompt
- `init.sql` — full schema (~860 lines, 22 tables, migrations 001-014)

**Protected files (NEVER modify):**
- `worker/sandbox/ast_prefilter.py`
- `worker/sandbox/seccomp_profile.json`
- `worker/sandbox/kill_timer.py`

**Conventions — follow ALL of these:**
- Temporal workflows: Use `workflow.unsafe.imports_passed_through()` for non-deterministic imports
- LLM calls: ALWAYS use the `get_tier_config()` + `log_llm_call()` + `get_version()` pattern from existing code
- Migrations: Sequential numbering (next is 015), applied via `cat file.sql | docker exec -i hydra-postgres psql -U hydra -d hydra`
- Linting: flake8 with `--max-line-length=200 --ignore=E501,W503,E402`
- Line endings: LF enforced via .gitattributes
- Postgres access: `docker compose exec -T postgres psql -U hydra -d hydra`
- Worker access: `docker compose exec -T worker python -c "..."`

---

## CTO CORRECTIONS (MUST apply all three)

1. **Investigation Memory: TWO-PASS matching only.** Exact value match first (fast, high confidence), then pgvector semantic search (slower, clearly marked as "similar — not identical"). NO CIDR /24 normalization for IPs. Per-entity-type similarity thresholds (tunable, logged).

2. **JSON enforcement: NO `response_format` API parameter.** Different LLM providers handle this inconsistently. Enforce JSON structure in the prompt text itself. Validate output in code via key checking.

3. **No SOAR real integrations.** Pilot runs in observation mode only. Existing 5 playbooks from Sprint 2B are sufficient for demo. Do NOT wire CrowdStrike, Okta, or any external API.

---

## EXECUTION PLAN — DAYS 1-14

### DAY 1: LiteLLM Fallback Configuration

**MODIFY** (not create) `litellm_config.yaml`:

```yaml
# litellm_config.yaml — MODIFIED for multi-provider fallback
# Previous: all tiers → single OpenRouter/Gemini Flash
# New: 3 tiers with provider-specific fallback chains

model_list:
  # === FAST TIER (entity extraction, skill parameters) ===
  - model_name: "hydra-fast"
    litellm_params:
      model: "groq/llama-3.1-8b-instant"
      api_key: "os.environ/GROQ_API_KEY"
      temperature: 0.1
      max_tokens: 1024

  - model_name: "hydra-fast-fallback"
    litellm_params:
      model: "openrouter/google/gemini-flash-1.5"
      api_key: "os.environ/OPENROUTER_API_KEY"
      temperature: 0.1
      max_tokens: 1024

  # === STANDARD TIER (code gen, reports, investigations) ===
  - model_name: "hydra-standard"
    litellm_params:
      model: "openrouter/google/gemini-pro-1.5"
      api_key: "os.environ/OPENROUTER_API_KEY"
      temperature: 0.3
      max_tokens: 4096

  - model_name: "hydra-standard-fallback"
    litellm_params:
      model: "anthropic/claude-sonnet-4-20250514"
      api_key: "os.environ/ANTHROPIC_API_KEY"
      temperature: 0.3
      max_tokens: 4096

  - model_name: "hydra-standard-emergency"
    litellm_params:
      model: "openai/gpt-4o-mini"
      api_key: "os.environ/OPENAI_API_KEY"
      temperature: 0.3
      max_tokens: 4096

  # === REASONING TIER (FP analysis, sigma rules, diagnosis) ===
  - model_name: "hydra-reasoning"
    litellm_params:
      model: "anthropic/claude-sonnet-4-20250514"
      api_key: "os.environ/ANTHROPIC_API_KEY"
      temperature: 0.2
      max_tokens: 4096

  - model_name: "hydra-reasoning-fallback"
    litellm_params:
      model: "openai/gpt-4o"
      api_key: "os.environ/OPENAI_API_KEY"
      temperature: 0.2
      max_tokens: 4096

router_settings:
  fallbacks:
    - {"hydra-fast": ["hydra-fast-fallback"]}
    - {"hydra-standard": ["hydra-standard-fallback", "hydra-standard-emergency"]}
    - {"hydra-reasoning": ["hydra-reasoning-fallback", "hydra-standard"]}
  allowed_fails: 3
  cooldown_time: 60
  timeout: 15
  retry_after: 5
  routing_strategy: "simple-shuffle"
  redis_host: "redis"
  redis_port: 6379

general_settings:
  master_key: "os.environ/LITELLM_MASTER_KEY"
  log_level: "INFO"
```

**MODIFY** `worker/model_config.py` — update `get_tier_config()` to return new model names:

```python
# Update the TIER_MAP to point to new LiteLLM model names
TIER_MAP = {
    'fast': 'hydra-fast',
    'standard': 'hydra-standard',
    'reasoning': 'hydra-reasoning',
}
```

Keep existing `get_tier_config()`, `log_llm_call()`, `get_version()` functions. Only change the model name mapping.

**MODIFY** `.env.example` — add new API key placeholders:

```
GROQ_API_KEY=gsk_your_key_here
OPENROUTER_API_KEY=sk-or-v1-your_key_here
ANTHROPIC_API_KEY=sk-ant-your_key_here
OPENAI_API_KEY=sk-your_key_here
LITELLM_MASTER_KEY=sk-litellm-hydra-dev
```

**MODIFY** `docker-compose.yml` — update existing litellm service to pass new env vars:

```yaml
  litellm:
    image: ghcr.io/berriai/litellm:main-latest
    volumes:
      - ./litellm_config.yaml:/app/config.yaml
    command: --config /app/config.yaml
    ports:
      - "4000:4000"
    environment:
      - GROQ_API_KEY=${GROQ_API_KEY}
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY}
    depends_on:
      - redis
    restart: unless-stopped
```

**VERIFY:** `docker compose up -d litellm; docker compose logs litellm --tail 20` — should show all models loaded.

---

### DAYS 2-3: Dry-Run Validation Gate

**CREATE** `worker/validation/dry_run.py`:

```python
"""
Dry-run validation gate for LLM-generated investigation code.
Executes code in ultra-restricted sandbox (5s timeout) before
committing to full investigation.

Uses existing sandbox infrastructure — NOT a new Docker implementation.
"""
import asyncio
import json
import subprocess
import tempfile
import os
import logging

logger = logging.getLogger(__name__)

REQUIRED_OUTPUT_KEYS = {'findings', 'confidence', 'entities', 'verdict'}


class DryRunValidator:
    """
    5-second pre-validation of LLM-generated code.
    Reuses the existing sandbox container approach with tighter limits.
    """

    def __init__(self, timeout: int = 5, memory_limit: str = "128m"):
        self.timeout = timeout
        self.memory_limit = memory_limit

    async def validate(self, code: str) -> dict:
        """
        Execute code in restricted subprocess, validate output.
        Returns: {'passed': bool, 'output': dict|None, 'reason': str|None}
        """
        # Step 1: Static checks (fast, no execution)
        static_result = self._static_checks(code)
        if not static_result['passed']:
            return static_result

        # Step 2: Dynamic dry-run in subprocess with timeout
        try:
            output = await self._execute_with_timeout(code)
        except asyncio.TimeoutError:
            return {'passed': False, 'output': None, 'reason': f'Dry-run exceeded {self.timeout}s timeout'}
        except Exception as e:
            return {'passed': False, 'output': None, 'reason': f'Dry-run execution error: {str(e)[:200]}'}

        # Step 3: Validate output schema
        if not isinstance(output, dict):
            return {'passed': False, 'output': None, 'reason': f'Output is not a dict: {type(output).__name__}'}

        missing = REQUIRED_OUTPUT_KEYS - set(output.keys())
        if missing:
            return {'passed': False, 'output': output, 'reason': f'Missing required keys: {missing}'}

        # Step 4: Validate value types
        if not isinstance(output.get('confidence'), (int, float)):
            return {'passed': False, 'output': output, 'reason': 'confidence must be a number'}

        if output.get('verdict') not in ('malicious', 'suspicious', 'benign', 'insufficient_data'):
            return {'passed': False, 'output': output, 'reason': f"Invalid verdict: {output.get('verdict')}"}

        return {'passed': True, 'output': output, 'reason': None}

    def _static_checks(self, code: str) -> dict:
        """Fast static analysis without execution."""
        # Check for obvious infinite loops
        if 'while True' in code and 'break' not in code:
            return {'passed': False, 'output': None, 'reason': 'Potential infinite loop detected (while True without break)'}

        # Check for network calls (should not be in dry-run)
        network_indicators = ['requests.get', 'requests.post', 'urllib', 'http.client', 'socket.connect']
        for indicator in network_indicators:
            if indicator in code:
                return {'passed': False, 'output': None, 'reason': f'Network call detected in investigation code: {indicator}'}

        # Check it's parseable Python
        try:
            compile(code, '<dry-run>', 'exec')
        except SyntaxError as e:
            return {'passed': False, 'output': None, 'reason': f'Syntax error: {e}'}

        return {'passed': True, 'output': None, 'reason': None}

    async def _execute_with_timeout(self, code: str) -> dict:
        """Execute code in subprocess with resource limits."""
        # Write code to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, dir='/tmp') as f:
            # Wrap code to capture output as JSON
            wrapper = f'''
import json
import sys
import resource

# Memory limit: 128MB
resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))

try:
    result = None
    # Execute the investigation code
{self._indent_code(code, spaces=4)}
    # Expect the code sets a 'result' variable or prints JSON
    if result is not None:
        print(json.dumps(result))
    else:
        print(json.dumps({{"error": "No result variable set"}}))
except Exception as e:
    print(json.dumps({{"error": str(e)}}))
    sys.exit(1)
'''
            f.write(wrapper)
            temp_path = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                'python', temp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout
            )

            if proc.returncode != 0:
                raise RuntimeError(f"Exit code {proc.returncode}: {stderr.decode()[:200]}")

            return json.loads(stdout.decode().strip())

        finally:
            os.unlink(temp_path)

    def _indent_code(self, code: str, spaces: int = 4) -> str:
        """Indent code block for wrapping."""
        prefix = ' ' * spaces
        return '\n'.join(prefix + line for line in code.split('\n'))
```

**CREATE** `worker/validation/__init__.py`:

```python
from worker.validation.dry_run import DryRunValidator

__all__ = ['DryRunValidator']
```

**MODIFY** `worker/activities.py` — add dry-run gate between `generate_code` and `execute_code`:

```python
# Add this import at top of activities.py
from worker.validation.dry_run import DryRunValidator

# Add this new activity
@activity.defn
async def validate_generated_code(code: str) -> dict:
    """Dry-run validation gate. Runs BEFORE full sandbox execution."""
    validator = DryRunValidator(timeout=5)
    result = await validator.validate(code)

    if not result['passed']:
        logger.warning(f"Dry-run validation failed: {result['reason']}")
        # Log to llm_call_log as validation_failure
        await log_llm_call(
            activity='validate_generated_code',
            model='dry-run',
            status='validation_failed',
            error=result['reason']
        )

    return result
```

**MODIFY** `worker/workflows.py` — wire the validation gate into `ExecuteTaskWorkflow`:

```python
# In the ExecuteTaskWorkflow, after generate_code and before execute_code:
# Add between existing steps:

    # Existing: code = await workflow.execute_activity(generate_code, ...)

    # NEW: Dry-run validation gate
    validation = await workflow.execute_activity(
        validate_generated_code,
        code,
        start_to_close_timeout=timedelta(seconds=15)
    )
    if not validation['passed']:
        # Re-generate with feedback (one retry only)
        code = await workflow.execute_activity(
            generate_code,
            {**task_input, 'validation_feedback': validation['reason']},
            start_to_close_timeout=timedelta(seconds=30)
        )
        # Validate again - if it fails again, mark investigation as failed
        validation2 = await workflow.execute_activity(
            validate_generated_code,
            code,
            start_to_close_timeout=timedelta(seconds=15)
        )
        if not validation2['passed']:
            return {'status': 'failed', 'reason': f"Code validation failed twice: {validation2['reason']}"}

    # Existing: execution_result = await workflow.execute_activity(execute_code, ...)
```

**VERIFY:** Submit a test alert → check worker logs for "Dry-run validation" entries.

---

### DAYS 3-4: Migration 015 — Seed Skills Table

**IMPORTANT:** Before writing this migration, inspect the actual `agent_skills` table schema:

```bash
docker compose exec -T postgres psql -U hydra -d hydra -c "\d agent_skills"
```

Then create `migrations/015_seed_agent_skills.sql` matching the ACTUAL column names. Expected content (adjust column names to match schema):

```sql
-- migrations/015_seed_agent_skills.sql
-- Sprint 5: Seed agent_skills with 5 core MSSP investigation types
-- Depends on: existing agent_skills table from Block 1 migrations

-- Verify table exists and is empty
DO $$
BEGIN
    IF (SELECT count(*) FROM agent_skills) > 0 THEN
        RAISE NOTICE 'agent_skills already has data, skipping seed';
        RETURN;
    END IF;

    INSERT INTO agent_skills (name, description, prompt_template, expected_entity_types, mitre_techniques, active, created_at) VALUES
    ('brute_force',
     'Investigate brute force and credential stuffing attacks. Analyze login patterns, source IPs, targeted accounts, and success/failure ratios.',
     'brute_force_investigation_v1',
     ARRAY['ip', 'user', 'device'],
     ARRAY['T1110', 'T1110.001', 'T1110.002', 'T1110.003', 'T1110.004'],
     true, NOW()),

    ('malware_triage',
     'Triage malware alerts. Analyze file hashes, process execution chains, network callbacks, and persistence mechanisms.',
     'malware_triage_v1',
     ARRAY['file_hash', 'process', 'ip', 'domain'],
     ARRAY['T1204', 'T1204.002', 'T1059', 'T1547'],
     true, NOW()),

    ('phishing_analysis',
     'Investigate phishing emails. Analyze sender domains, URLs, attachments, and recipient interaction patterns.',
     'phishing_analysis_v1',
     ARRAY['domain', 'url', 'email', 'file_hash'],
     ARRAY['T1566', 'T1566.001', 'T1566.002'],
     true, NOW()),

    ('lateral_movement',
     'Detect lateral movement. Analyze authentication patterns across hosts, RDP/SMB connections, and credential usage.',
     'lateral_movement_v1',
     ARRAY['ip', 'user', 'process', 'device'],
     ARRAY['T1021', 'T1021.001', 'T1021.002', 'T1076'],
     true, NOW()),

    ('c2_communication',
     'Detect command-and-control communication. Analyze beaconing patterns, DNS tunneling, and unusual outbound connections.',
     'c2_communication_v1',
     ARRAY['ip', 'domain', 'process', 'url'],
     ARRAY['T1071', 'T1071.001', 'T1071.004', 'T1573'],
     true, NOW());

    RAISE NOTICE 'Seeded 5 investigation skills into agent_skills';
END $$;
```

**Register new prompts** via `worker/prompt_init.py` — add the 5 skill prompt templates to the existing prompt registration system (use the existing `get_version()` SHA256 pattern).

**Apply:** `cat migrations/015_seed_agent_skills.sql | docker exec -i hydra-postgres psql -U hydra -d hydra`

**VERIFY:** `docker compose exec -T postgres psql -U hydra -d hydra -c "SELECT name, active FROM agent_skills"`  → should return 5 rows.

---

### DAYS 4-5: Investigation Memory

**CREATE** `worker/investigation_memory.py`:

```python
"""
Investigation Memory — Pre-investigation enrichment.
Two-pass matching: exact first, then pgvector semantic search.
Wired into ExecuteTaskWorkflow as Step 0.

CTO CORRECTIONS APPLIED:
- NO CIDR normalization for IPs (exact match only in Pass 1)
- Per-entity-type similarity thresholds (tunable, logged)
- pgvector distance threshold NOT hardcoded — configurable
"""
import logging
import os
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Tunable per entity type — log every match to calibrate during pilot
SIMILARITY_THRESHOLDS = {
    'ip': 0.15,
    'domain': 0.20,
    'file_hash': 0.10,
    'user': 0.25,
    'process': 0.20,
    'url': 0.20,
    'email': 0.20,
}

# Override from env if needed
SIMILARITY_OVERRIDE = float(os.environ.get('HYDRA_SIMILARITY_THRESHOLD', '0'))


class InvestigationMemory:
    """Pre-investigation enrichment with exact + semantic matching."""

    def __init__(self, db_pool, embedding_url: str = 'http://embedding-server:80'):
        self.db_pool = db_pool
        self.embedding_url = embedding_url

    async def enrich_alert(self, alert_entities: List[Dict]) -> Dict:
        """
        Two-pass enrichment for extracted alert IOCs.
        Returns: {exact_matches: [...], similar_entities: [...], related_investigations: set()}
        """
        memory = {
            'exact_matches': [],
            'similar_entities': [],
            'related_investigations': set()
        }

        for entity in alert_entities:
            etype = entity.get('type', 'unknown')
            evalue = entity.get('value', '')

            if not evalue:
                continue

            # PASS 1: Exact value match (high confidence, fast)
            exact = await self._exact_match(etype, evalue)
            if exact:
                memory['exact_matches'].append({
                    'entity': evalue,
                    'type': etype,
                    'conclusion': exact['verdict'],
                    'confidence': float(exact['confidence'] or 0),
                    'investigation_id': str(exact['investigation_id']),
                    'seen_at': str(exact['created_at']),
                    'match_type': 'exact'
                })
                memory['related_investigations'].add(str(exact['investigation_id']))
                continue  # Skip semantic if exact match found

            # PASS 2: Semantic search via pgvector (lower confidence, clearly labeled)
            similar = await self._semantic_search(etype, evalue)
            if similar:
                memory['similar_entities'].append({
                    'entity': evalue,
                    'similar_to': similar['entity_value'],
                    'type': etype,
                    'conclusion': similar['verdict'],
                    'confidence': float(similar['confidence'] or 0) * 0.8,  # Discount for fuzzy match
                    'investigation_id': str(similar['investigation_id']),
                    'distance': float(similar['distance']),
                    'match_type': 'similar'
                })
                memory['related_investigations'].add(str(similar['investigation_id']))

                logger.info(
                    f"Semantic match: {evalue} ~ {similar['entity_value']} "
                    f"(type={etype}, dist={similar['distance']:.4f}, "
                    f"threshold={self._get_threshold(etype)})"
                )

        # Convert set to list for JSON serialization
        memory['related_investigations'] = list(memory['related_investigations'])
        return memory

    async def _exact_match(self, entity_type: str, entity_value: str) -> Optional[Dict]:
        """
        Exact value match — NO normalization.
        Joins entity_observations → investigations to get verdict + confidence.
        """
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    e.value as entity_value,
                    e.type as entity_type,
                    eo.investigation_id,
                    eo.created_at,
                    i.verdict,
                    i.confidence
                FROM entities e
                JOIN entity_observations eo ON eo.entity_id = e.id
                JOIN investigations i ON i.id = eo.investigation_id
                WHERE e.type = $1
                  AND e.value = $2
                  AND i.verdict IS NOT NULL
                ORDER BY eo.created_at DESC
                LIMIT 1
            """, entity_type, entity_value)
            return dict(row) if row else None

    async def _semantic_search(self, entity_type: str, entity_value: str) -> Optional[Dict]:
        """
        pgvector cosine distance search with per-type threshold.
        Uses existing embedding-server (TEI nomic-embed-text-v1.5 on port 80).
        """
        embedding = await self._get_embedding(entity_value)
        if embedding is None:
            return None

        threshold = self._get_threshold(entity_type)

        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    e.value as entity_value,
                    e.type as entity_type,
                    eo.investigation_id,
                    eo.created_at,
                    i.verdict,
                    i.confidence,
                    e.embedding <-> $1 as distance
                FROM entities e
                JOIN entity_observations eo ON eo.entity_id = e.id
                JOIN investigations i ON i.id = eo.investigation_id
                WHERE e.type = $2
                  AND e.value != $3
                  AND e.embedding IS NOT NULL
                  AND e.embedding <-> $1 < $4
                  AND i.verdict IS NOT NULL
                ORDER BY e.embedding <-> $1
                LIMIT 1
            """, embedding, entity_type, entity_value, threshold)
            return dict(row) if row else None

    async def _get_embedding(self, text: str) -> Optional[list]:
        """Get embedding from existing TEI embedding-server."""
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.embedding_url}/embed",
                    json={"inputs": text},
                    timeout=5.0
                )
                resp.raise_for_status()
                # TEI returns list of embeddings, take first
                embeddings = resp.json()
                return embeddings[0] if embeddings else None
        except Exception as e:
            logger.warning(f"Embedding request failed for '{text}': {e}")
            return None

    def _get_threshold(self, entity_type: str) -> float:
        """Get similarity threshold — env override or per-type default."""
        if SIMILARITY_OVERRIDE > 0:
            return SIMILARITY_OVERRIDE
        return SIMILARITY_THRESHOLDS.get(entity_type, 0.20)
```

**CREATE** `worker/prompts/investigation_prompt.py`:

```python
"""
Investigation prompt template with memory context injection.
Registers with existing prompt_registry.py via get_version() SHA256 pattern.
JSON enforcement is IN THE PROMPT TEXT — NOT via API response_format parameter.
"""

INVESTIGATION_PROMPT_V1 = """You are a SOC analyst investigating a security alert.

ALERT CONTEXT:
Alert Type: {alert_type}
Source: {source}
Timestamp: {timestamp}
Raw Data:
{raw_data}

{memory_section}

YOUR TASK:
Analyze this alert and produce investigation findings. You MUST respond with
ONLY valid JSON (no markdown, no code fences, no explanation outside the JSON).

Required JSON structure:
{{
  "findings": ["string describing each finding"],
  "confidence": <float 0.0-1.0>,
  "entities": [
    {{"type": "ip|domain|file_hash|user|process|url|email", "value": "...", "context": "..."}}
  ],
  "verdict": "malicious|suspicious|benign|insufficient_data",
  "recommended_actions": ["action1", "action2"],
  "reasoning": "Brief explanation of your conclusion"
}}

IMPORTANT: Output ONLY the JSON object. No other text."""


def build_investigation_prompt(alert: dict, memory: dict = None) -> str:
    """Build prompt with optional memory enrichment."""
    memory_section = _format_memory(memory) if memory else "PRIOR INTELLIGENCE: No prior investigations found for these indicators."

    return INVESTIGATION_PROMPT_V1.format(
        alert_type=alert.get('task_type', alert.get('type', 'unknown')),
        source=alert.get('source', 'SIEM'),
        timestamp=alert.get('timestamp', 'N/A'),
        raw_data=str(alert.get('input', alert.get('raw_data', '')))[:2000],
        memory_section=memory_section
    )


def _format_memory(memory: dict) -> str:
    """Format memory context for prompt injection."""
    lines = ["PRIOR INTELLIGENCE FROM INVESTIGATION MEMORY:"]

    if memory.get('exact_matches'):
        lines.append("\nEXACT MATCHES (High Confidence — same indicator seen before):")
        for m in memory['exact_matches']:
            lines.append(
                f"  - {m['type'].upper()} {m['entity']}: "
                f"Previously concluded '{m['conclusion']}' "
                f"(confidence: {m['confidence']:.2f}, "
                f"investigation: {m['investigation_id']}, "
                f"seen: {m['seen_at']})"
            )

    if memory.get('similar_entities'):
        lines.append("\nSIMILAR INDICATORS (Lower Confidence — review recommended):")
        for m in memory['similar_entities']:
            lines.append(
                f"  - {m['type'].upper()} {m['entity']} similar to {m['similar_to']}: "
                f"Prior conclusion '{m['conclusion']}' "
                f"(adjusted confidence: {m['confidence']:.2f}, "
                f"similarity distance: {m['distance']:.4f})"
            )

    if not memory.get('exact_matches') and not memory.get('similar_entities'):
        lines.append("  No relevant prior investigations found.")

    return "\n".join(lines)
```

---

### DAYS 5-6: Wire Memory into ExecuteTaskWorkflow

**MODIFY** `worker/workflows.py` — add memory enrichment as Step 0:

```python
# At top of file, inside workflow.unsafe.imports_passed_through():
# Add imports for new modules

# Add new activity in activities.py:
@activity.defn
async def enrich_alert_with_memory(task_input: dict) -> dict:
    """Step 0: Check investigation memory before generating code."""
    from worker.investigation_memory import InvestigationMemory

    # Extract entities from alert input (IPs, domains, hashes in the raw data)
    raw_entities = _extract_iocs_from_input(task_input)

    if not raw_entities:
        return {'exact_matches': [], 'similar_entities': [], 'related_investigations': []}

    memory = InvestigationMemory(
        db_pool=get_db_pool(),
        embedding_url='http://embedding-server:80'
    )
    return await memory.enrich_alert(raw_entities)


def _extract_iocs_from_input(task_input: dict) -> list:
    """Quick regex extraction of IOCs from alert input for memory lookup."""
    import re
    entities = []
    text = str(task_input)

    # IPs
    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        if not ip.startswith(('0.', '127.', '255.')):
            entities.append({'type': 'ip', 'value': ip})

    # Domains
    for domain in re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b', text):
        if '.' in domain and not domain[0].isdigit():
            entities.append({'type': 'domain', 'value': domain.lower()})

    # SHA256 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{64}\b', text):
        entities.append({'type': 'file_hash', 'value': h.lower()})

    # MD5 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{32}\b', text):
        entities.append({'type': 'file_hash', 'value': h.lower()})

    return entities
```

**In ExecuteTaskWorkflow**, add before existing `generate_code` step:

```python
    # STEP 0: Memory enrichment (new)
    memory = await workflow.execute_activity(
        enrich_alert_with_memory,
        task_input,
        start_to_close_timeout=timedelta(seconds=10)
    )

    # STEP 1: Build prompt with memory context (modified)
    from worker.prompts.investigation_prompt import build_investigation_prompt
    prompt = build_investigation_prompt(task_input, memory)

    # STEP 2: Generate code — existing generate_code activity, now with enriched prompt
    # ... existing code continues, passing enriched prompt
```

**VERIFY:** Submit a known IOC (e.g., an IP that exists in the entity graph) → check worker logs for "Semantic match" or "exact match" entries.

---

### DAY 7: Integration Tests

**CREATE** `tests/integration/test_sprint5.py`:

```python
"""
Sprint 5 integration tests.
Run inside worker container:
  docker compose exec -T worker python -m pytest tests/integration/test_sprint5.py -v
"""
import pytest
import asyncio
import json


class TestLiteLLMFallback:
    """Test 1: LiteLLM fallback chain works."""

    @pytest.mark.asyncio
    async def test_standard_tier_responds(self):
        """Verify hydra-standard tier returns a response."""
        from litellm import Router
        import yaml
        with open('/app/litellm_config.yaml') as f:
            config = yaml.safe_load(f)
        router = Router(model_list=config['model_list'])
        response = await router.acompletion(
            model="hydra-standard",
            messages=[{"role": "user", "content": "Respond with: {\"test\": true}"}],
            timeout=15
        )
        assert response.choices[0].message.content is not None


class TestDryRunGate:
    """Test 2-3: Dry-run validation catches bad code."""

    @pytest.mark.asyncio
    async def test_missing_keys_rejected(self):
        """Code that returns wrong keys should fail validation."""
        from worker.validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        bad_code = 'result = {"wrong_key": "bad"}'
        result = await validator.validate(bad_code)
        assert not result['passed']
        assert 'Missing required keys' in result['reason']

    @pytest.mark.asyncio
    async def test_valid_code_passes(self):
        """Code with correct keys should pass."""
        from worker.validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        good_code = '''result = {
    "findings": ["Test finding"],
    "confidence": 0.95,
    "entities": [{"type": "ip", "value": "1.2.3.4", "context": "test"}],
    "verdict": "benign"
}'''
        result = await validator.validate(good_code)
        assert result['passed']

    @pytest.mark.asyncio
    async def test_infinite_loop_rejected(self):
        """Code with infinite loop should fail static check."""
        from worker.validation.dry_run import DryRunValidator
        validator = DryRunValidator(timeout=5)
        bad_code = 'while True:\n    pass'
        result = await validator.validate(bad_code)
        assert not result['passed']


class TestInvestigationMemory:
    """Test 4-5: Memory exact match and semantic search."""

    @pytest.mark.asyncio
    async def test_exact_match_returns_prior(self):
        """If an IP exists in entity graph, exact match should find it."""
        # This test requires the bootstrap data (304 entities)
        # Query directly to verify the entity_observations JOIN works
        pass  # Implement after verifying actual schema columns

    @pytest.mark.asyncio
    async def test_semantic_search_finds_similar(self):
        """Similar domain should match via pgvector."""
        pass  # Implement after verifying embedding distances


class TestSkillRouting:
    """Test 6: Correct skill selected for alert type."""

    @pytest.mark.asyncio
    async def test_brute_force_selects_correct_skill(self):
        """Brute force alert should select brute_force skill."""
        # Query agent_skills table
        pass  # Implement after migration 015 applied


class TestGoldenPath:
    """Test 7: Full workflow end-to-end."""

    @pytest.mark.asyncio
    async def test_alert_to_investigation_completes(self):
        """Submit alert → verify investigation completes with entities."""
        # This is a full Temporal workflow test
        # Submit via API, poll for completion
        pass  # Implement as Temporal workflow test
```

**VERIFY:** `docker compose exec -T worker python -m pytest tests/integration/test_sprint5.py -v`

---

### DAYS 8-10: Dashboard — Investigation Waterfall

**MODIFY** `dashboard/` React app. Create three views:

**View 1: Investigation Waterfall (WebSocket real-time)**
- Connect to Go API WebSocket endpoint for investigation step updates
- Show cascading timeline: Alert → Code Gen → Sandbox → Entities → Verdict
- Each step shows timestamp, duration, status (running/complete/failed)
- Use React state to update steps as WebSocket messages arrive

**View 2: Entity Graph (D3.js force-directed)**
- Fetch entities + edges from Go API: `GET /api/v1/entities?tenant_id=...`
- D3 force-directed graph with nodes colored by type, sized by threat score
- Click node → sidebar showing all investigations involving this entity (Memory!)
- Edge labels showing relationship types

**View 3: Investigation Report Viewer**
- Fetch report markdown from Go API: `GET /api/v1/investigations/:id/report`
- Render markdown with react-markdown
- "Export to PDF" button using existing MinIO-stored PDFs

**NOTE:** The Go API may need new endpoints for WebSocket investigation updates and entity graph queries. Check existing API routes first (`grep -r "HandleFunc\|router\." api/`), add only what's missing.

---

### DAYS 11-12: Entity Graph Endpoints + Report Viewer

Add to Go API if not already present:
- `GET /api/v1/investigations/:id/steps` — investigation step timeline
- `GET /api/v1/entities/graph?tenant_id=` — entity nodes + edges for D3
- `GET /api/v1/investigations/:id/report` — markdown report content
- `WS /api/v1/investigations/:id/live` — WebSocket for real-time step updates

---

### DAY 13: Demo Scenarios

**CREATE** `demo/scenarios.json`:

```json
{
  "scenarios": [
    {
      "name": "SSH Brute Force → Lateral Movement",
      "alert": {
        "task_type": "brute_force",
        "input": {
          "prompt": "Investigate 847 failed SSH login attempts from 203.0.113.50 targeting server admin accounts over the past 30 minutes. The last 3 attempts succeeded."
        }
      },
      "expected_verdict": "malicious",
      "demo_duration_seconds": 90
    },
    {
      "name": "Phishing Email → C2 Discovery",
      "alert": {
        "task_type": "phishing",
        "input": {
          "prompt": "Analyze suspicious email from invoice-update@acm3corp.com containing attachment 'Q3_Report.pdf.exe' (SHA256: a1b2c3...). 3 users clicked the link to hxxp://acm3corp.com/download."
        }
      },
      "expected_verdict": "malicious",
      "demo_duration_seconds": 90
    },
    {
      "name": "Ransomware Indicators → Blast Radius",
      "alert": {
        "task_type": "malware",
        "input": {
          "prompt": "Endpoint alert: Process 'svchost_update.exe' encrypting files on WORKSTATION-042. Outbound connection to 198.51.100.77:4443. Shadow copies deleted via vssadmin."
        }
      },
      "expected_verdict": "malicious",
      "demo_duration_seconds": 120
    }
  ]
}
```

**CREATE** demo mode in dashboard: A `/demo` route that auto-submits scenarios with a "Start Demo" button. Non-technical user can run it unassisted.

---

### DAY 14: Alert Deduplication Layer 1

**CREATE** `migrations/016_alert_fingerprints.sql`:

```sql
-- migrations/016_alert_fingerprints.sql
-- Sprint 5: Alert deduplication via composite fingerprinting
-- Layer 1: Exact-match SHA-256 fingerprint on normalized alert fields

CREATE TABLE IF NOT EXISTS alert_fingerprints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    fingerprint     VARCHAR(64) NOT NULL,  -- SHA-256 hex
    alert_type      VARCHAR(100) NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_count     INTEGER NOT NULL DEFAULT 1,
    investigation_id UUID REFERENCES investigations(id),
    dedup_window_seconds INTEGER NOT NULL DEFAULT 900,  -- 15 min default
    raw_sample      JSONB,  -- first alert payload for reference
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_alert_fp_tenant_hash
    ON alert_fingerprints(tenant_id, fingerprint)
    WHERE last_seen > NOW() - INTERVAL '24 hours';

CREATE INDEX idx_alert_fp_last_seen
    ON alert_fingerprints(last_seen);

COMMENT ON TABLE alert_fingerprints IS 'Layer 1 alert deduplication. SHA-256 fingerprint of normalized alert fields. Dedup window configurable per tenant.';
```

**MODIFY** Go API alert ingestion — before creating an `agent_task`:

```
1. Extract fingerprint fields: (tenant_id, alert_type, source_ip, dest_ip, rule_name)
2. Normalize: lowercase, trim whitespace, sort
3. SHA-256 hash the concatenated string
4. Check alert_fingerprints for matching (tenant_id, fingerprint) within dedup_window
5. If match: UPDATE last_seen, INCREMENT alert_count, RETURN existing investigation_id
6. If no match: INSERT new fingerprint, proceed to create agent_task + investigation
```

**VERIFY:** Submit the same brute force alert 10 times rapidly → only 1 investigation created, `alert_count` = 10.

---

## ENVIRONMENT VARIABLES TO ADD TO .env

```
GROQ_API_KEY=gsk_...
OPENROUTER_API_KEY=sk-or-v1-...
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
LITELLM_MASTER_KEY=sk-litellm-hydra-dev
HYDRA_SIMILARITY_THRESHOLD=0  # 0 = use per-type defaults
```

---

## VERIFICATION CHECKLIST (run after each day)

```bash
# Day 1: LiteLLM routing
docker compose up -d litellm; docker compose logs litellm --tail 20

# Days 2-3: Dry-run gate
docker compose exec -T worker python -c "
import asyncio
from worker.validation.dry_run import DryRunValidator
v = DryRunValidator(timeout=5)
result = asyncio.run(v.validate('result = {\"findings\": [\"test\"], \"confidence\": 0.9, \"entities\": [], \"verdict\": \"benign\"}'))
print(result)
"

# Days 3-4: Skills seeded
docker compose exec -T postgres psql -U hydra -d hydra -c "SELECT name, active FROM agent_skills"

# Days 4-5: Memory module
docker compose exec -T worker python -c "
from worker.investigation_memory import InvestigationMemory
print('InvestigationMemory imported successfully')
"

# Day 7: Tests
docker compose exec -T worker python -m pytest tests/integration/test_sprint5.py -v

# Day 14: Dedup
docker compose exec -T postgres psql -U hydra -d hydra -c "SELECT count(*) FROM alert_fingerprints"
```

---

## ERRATA — 11 Corrections from Brainiac's Original Prompt

| # | Brainiac Error | Correction | Why It Matters |
|---|---|---|---|
| 1 | File paths use `hydra/core/`, `hydra/investigation/` | All worker files live in `worker/` directory | Wrong paths = import errors, nothing runs |
| 2 | "Create litellm_config.yaml" | MODIFY — file already exists | Would overwrite existing working config |
| 3 | "Add to docker-compose.yml" litellm service | MODIFY — service already exists | Would create duplicate service definition |
| 4 | Bypasses `get_tier_config()` + `log_llm_call()` + `get_version()` | MUST use existing LLM call conventions | Breaks observability, prompt versioning, and cost tracking |
| 5 | DryRunSandbox uses `docker.from_env()` (Docker-in-Docker) | Use subprocess with resource limits | Docker-in-Docker adds 2-5s container startup overhead to every dry-run, defeating the 5s budget |
| 6 | Model strings: `claude-3-sonnet-20240229`, `claude-3-opus-20240229` | Use current: `claude-sonnet-4-20250514` | Stale model strings may route to deprecated endpoints |
| 7 | entity_observations query assumes `conclusion`, `confidence` columns | Must JOIN entities → entity_observations → investigations | Wrong columns = query fails, memory returns nothing |
| 8 | IP normalization uses CIDR /24 | Exact match only (CTO correction) | /24 normalization creates false positives (gateway vs workstation) |
| 9 | pgvector threshold hardcoded at 0.25 | Per-type thresholds + env override | Single threshold doesn't work across entity types |
| 10 | Uses `response_format: {"type": "json_object"}` | JSON enforcement in prompt text only | Provider-dependent — Gemini via OpenRouter ignores this param |
| 11 | No schema verification before migration | Must `\d agent_skills` before writing INSERT | Wrong column names = migration fails silently |
