# HYDRA Sprint 1I — Model Tiering + Prompt Versioning
## Claude Code Prompt

---

You are building Sprint 1I for HYDRA, an AI-powered SOC investigation automation platform. This sprint implements model tiering (right-sized models for each task type) and prompt versioning (every prompt version tracked and tied to investigation outcomes). These are prerequisites for the future fine-tuned security model (Layer 5 of the moat roadmap).

## Context

Currently HYDRA routes all LLM calls through LiteLLM to a single "fast" model (Qwen2.5-1.5B via OpenRouter or local vLLM). But different tasks have very different quality requirements — template parameter extraction doesn't need 7B, while code generation and risk assessment suffer at 1.5B (inconsistent risk scores, malformed JSON).

Sprint 1F added the `llm_call_log` table that captures every LLM input/output pair. Sprint 1I builds on that by routing calls to the right model and versioning every prompt.

## Deliverables

### 1I-1: Model Tier Configuration

Create `worker/model_config.py`:

```python
MODEL_TIERS = {
    "fast": {
        "model": "openrouter/qwen/qwen-2.5-1.5b-instruct",
        "local": "ollama/qwen2.5:1.5b",
        "max_tokens": 1024,
        "temperature": 0.1,
        "use_for": ["parameter_fill", "simple_extraction"]
    },
    "standard": {
        "model": "openrouter/qwen/qwen-2.5-7b-instruct",
        "local": "ollama/qwen2.5:7b",
        "max_tokens": 2048,
        "temperature": 0.2,
        "use_for": ["code_generation", "entity_extraction"]
    },
    "reasoning": {
        "model": "openrouter/qwen/qwen-2.5-32b-instruct",
        "local": "ollama/qwen2.5:32b",
        "max_tokens": 4096,
        "temperature": 0.3,
        "use_for": ["complex_investigation", "risk_assessment", "attack_chain_analysis"]
    }
}

TASK_TO_TIER = {
    "fill_skill_parameters": "fast",
    "render_skill_template": "fast",
    "generate_code": "standard",
    "generate_followup_code": "standard",
    "extract_entities": "standard",
    "risk_assessment": "reasoning",
    "attack_chain_analysis": "reasoning",
}
```

- Add `HYDRA_MODEL_MODE` env var: `cloud` (use OpenRouter), `local` (use Ollama/vLLM), `airgap` (use local only, fail if unavailable)
- Add `HYDRA_FORCE_MODEL` env var: if set, override all tiers with this model (for testing/cost control)
- Update all LiteLLM calls in `activities.py` and `entity_graph.py` to use `get_model_for_task(task_type)` instead of hardcoded "fast"

### 1I-2: Prompt Registry

Create `worker/prompt_registry.py`:

Every prompt used in HYDRA gets registered with a version hash:

```python
import hashlib

class PromptRegistry:
    _prompts = {}
    
    @classmethod
    def register(cls, name: str, system_prompt: str, user_template: str) -> str:
        """Register a prompt and return its version hash."""
        content = f"{system_prompt}\n---\n{user_template}"
        version = hashlib.sha256(content.encode()).hexdigest()[:12]
        cls._prompts[name] = {
            "system_prompt": system_prompt,
            "user_template": user_template,
            "version": version,
            "name": name
        }
        return version
    
    @classmethod
    def get(cls, name: str) -> dict:
        """Get prompt by name."""
        return cls._prompts[name]
    
    @classmethod
    def get_version(cls, name: str) -> str:
        """Get version hash for a prompt."""
        return cls._prompts[name]["version"]
```

Register all existing prompts:
- `code_generation` — the system prompt used in generate_code activity
- `followup_generation` — the system prompt for generate_followup_code
- `entity_extraction` — from worker/prompts/entity_extraction.py
- `parameter_fill` — from fill_skill_parameters activity
- `skill_template_render` — from render_skill_template activity

Update all LLM calls to:
1. Get prompt from registry
2. Include `prompt_version` in the llm_call_log entry
3. Include `prompt_version` in investigation record

### 1I-3: Model Performance Tracking

Create a view or materialized view that aggregates model performance:

```sql
CREATE MATERIALIZED VIEW IF NOT EXISTS model_performance AS
SELECT 
    model_id,
    prompt_version,
    call_type,
    COUNT(*) as total_calls,
    AVG(latency_ms) as avg_latency_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95_latency_ms,
    AVG(input_tokens) as avg_input_tokens,
    AVG(output_tokens) as avg_output_tokens,
    SUM(CASE WHEN output_valid THEN 1 ELSE 0 END)::FLOAT / COUNT(*) as schema_success_rate,
    DATE_TRUNC('day', created_at) as day
FROM llm_call_log
GROUP BY model_id, prompt_version, call_type, DATE_TRUNC('day', created_at);

CREATE UNIQUE INDEX idx_model_perf ON model_performance(model_id, prompt_version, call_type, day);
```

Add a CLI command: `python -m worker.model_config --report` that prints:
- Per-model: avg latency, token usage, schema success rate
- Per-prompt: success rate by version
- Recommendations: which tasks could be downgraded to a cheaper model

### 1I-4: LiteLLM Fallback Chain

Update LiteLLM configuration (litellm_config.yaml or equivalent) to add fallback:

```yaml
model_list:
  - model_name: standard
    litellm_params:
      model: openrouter/qwen/qwen-2.5-7b-instruct
      api_key: os.environ/OPENROUTER_API_KEY
    model_info:
      mode: chat
  - model_name: standard
    litellm_params:
      model: ollama/qwen2.5:7b
    model_info:
      mode: chat

router_settings:
  routing_strategy: simple-shuffle  # tries first, falls back to second
  num_retries: 2
  timeout: 60
```

If primary model (OpenRouter) fails → fall back to local model (Ollama/vLLM) → if that fails → fail the activity (Temporal will retry).

### 1I-5: Context Window Management

Different models have different context windows. Add smart truncation:

- 1.5B models: 4K context → truncate investigation output to 2500 chars
- 7B models: 32K context → truncate to 12000 chars  
- 32B models: 32K context → truncate to 12000 chars

Create `worker/context_manager.py`:
```python
def prepare_context(text: str, model_tier: str, reserved_tokens: int = 500) -> str:
    """Truncate text to fit model context window, preserving start and end."""
    limits = {"fast": 2500, "standard": 12000, "reasoning": 12000}
    max_chars = limits.get(model_tier, 3000)
    if len(text) <= max_chars:
        return text
    # Keep first 70% and last 30% with truncation marker
    head = int(max_chars * 0.7)
    tail = max_chars - head - 50  # 50 chars for marker
    return f"{text[:head]}\n\n[... {len(text) - max_chars} characters truncated ...]\n\n{text[-tail:]}"
```

Update the hardcoded 3000-char truncation in `entity_extraction.py` to use this.

## Important Constraints

- Model tiering must be transparent to Temporal workflows — the activity decides which model to use, not the workflow
- All model/prompt decisions must be logged in llm_call_log for future analysis
- Air-gap mode must gracefully degrade: if the preferred model isn't available locally, use whatever is available
- Don't change the LiteLLM Docker service configuration unless necessary — prefer client-side routing
- Cost tracking: add estimated cost per call based on token count × model pricing

## Definition of Done

- [ ] Different models used for different task types (verify via llm_call_log: model_id varies by call_type)
- [ ] All prompts registered with version hashes
- [ ] prompt_version populated on all new investigation records
- [ ] Model performance view created and queryable
- [ ] Fallback chain works: kill OpenRouter connectivity, verify local model takes over
- [ ] Context truncation uses model-appropriate limits
- [ ] `python -m worker.model_config --report` prints performance summary
- [ ] Git commit: "Sprint 1I: Model tiering + prompt versioning + fallback chain"
