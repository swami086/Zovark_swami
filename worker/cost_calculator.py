# cost_calculator.py — Per-model cost calculation for LLM calls

COST_PER_1K = {
    # Fast tier (Groq)
    'hydra-fast': {'input': 0.0002, 'output': 0.0002},
    'groq/llama-3.1-8b-instant': {'input': 0.0002, 'output': 0.0002},
    # Fast fallback (Gemini Flash)
    'hydra-fast-fallback': {'input': 0.001, 'output': 0.002},
    'openrouter/google/gemini-flash-1.5': {'input': 0.001, 'output': 0.002},
    # Standard tier (Gemini Pro)
    'hydra-standard': {'input': 0.003, 'output': 0.015},
    'openrouter/google/gemini-pro-1.5': {'input': 0.003, 'output': 0.015},
    # Standard fallback (Claude Sonnet)
    'hydra-standard-fallback': {'input': 0.003, 'output': 0.015},
    'anthropic/claude-sonnet-4-20250514': {'input': 0.003, 'output': 0.015},
    # Standard emergency (GPT-4o-mini)
    'hydra-standard-emergency': {'input': 0.00015, 'output': 0.0006},
    'openai/gpt-4o-mini': {'input': 0.00015, 'output': 0.0006},
    # Reasoning tier (Claude Sonnet)
    'hydra-reasoning': {'input': 0.003, 'output': 0.015},
    # Reasoning fallback (GPT-4o)
    'hydra-reasoning-fallback': {'input': 0.005, 'output': 0.015},
    'openai/gpt-4o': {'input': 0.005, 'output': 0.015},
    # Air-gap (Ollama — free, local)
    'hydra-fast-airgap': {'input': 0.0, 'output': 0.0},
    'hydra-standard-airgap': {'input': 0.0, 'output': 0.0},
    'hydra-reasoning-airgap': {'input': 0.0, 'output': 0.0},
    'ollama/qwen2.5:7b': {'input': 0.0, 'output': 0.0},
    # Legacy
    'fast': {'input': 0.0002, 'output': 0.0002},
}

# Default rate for unknown models
DEFAULT_RATE = {'input': 0.01, 'output': 0.03}


def calculate_cost(model, input_tokens, output_tokens):
    """Calculate USD cost for an LLM call."""
    rates = COST_PER_1K.get(model, DEFAULT_RATE)
    return (input_tokens * rates['input'] + output_tokens * rates['output']) / 1000
