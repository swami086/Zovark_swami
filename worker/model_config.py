"""Model tiering configuration — 3-tier routing for LLM calls.

Tiers:
- fast: Low-latency, cost-efficient (entity extraction, parameter filling)
- standard: Balanced (code generation, report writing)
- reasoning: High-quality (complex analysis, FP reasoning)

No Pydantic — plain dicts only.
"""

import os

# Default model (overridden by HYDRA_LLM_MODEL env var)
_DEFAULT_MODEL = os.environ.get("HYDRA_LLM_MODEL", "fast")

# Tier definitions
MODEL_TIERS = {
    "fast": {
        "model": _DEFAULT_MODEL,
        "max_tokens": 1024,
        "temperature": 0.1,
        "description": "Low-latency tasks: entity extraction, parameter filling, memory synthesis",
    },
    "standard": {
        "model": _DEFAULT_MODEL,
        "max_tokens": 4096,
        "temperature": 0.3,
        "description": "Balanced tasks: code generation, report writing, synthetic investigations",
    },
    "reasoning": {
        "model": _DEFAULT_MODEL,
        "max_tokens": 4096,
        "temperature": 0.2,
        "description": "Complex analysis: FP reasoning, deobfuscation, multi-step chains",
    },
}

# Activity → tier mapping
ACTIVITY_TIER_MAP = {
    # Fast tier
    "extract_entities": "fast",
    "fill_skill_parameters": "fast",
    "write_investigation_memory": "fast",
    # Standard tier
    "generate_code": "standard",
    "generate_followup_code": "standard",
    "generate_incident_report": "standard",
    "generate_synthetic_investigation": "standard",
    # Reasoning tier
    "analyze_false_positive": "reasoning",
    "generate_sigma_rule": "reasoning",
}


def get_tier_config(activity_name: str) -> dict:
    """Get model config for an activity.

    Returns dict with: model, max_tokens, temperature, tier
    """
    tier_name = ACTIVITY_TIER_MAP.get(activity_name, "fast")
    config = MODEL_TIERS[tier_name].copy()
    config["tier"] = tier_name
    # Allow env override for model
    env_model = os.environ.get("HYDRA_LLM_MODEL")
    if env_model:
        config["model"] = env_model
    return config


def get_model_for_activity(activity_name: str) -> str:
    """Get model ID for an activity."""
    return get_tier_config(activity_name)["model"]


def get_temperature_for_activity(activity_name: str) -> float:
    """Get temperature for an activity."""
    return get_tier_config(activity_name)["temperature"]


def get_max_tokens_for_activity(activity_name: str) -> int:
    """Get max_tokens for an activity."""
    return get_tier_config(activity_name)["max_tokens"]
