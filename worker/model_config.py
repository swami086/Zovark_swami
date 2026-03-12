"""Model tiering configuration — 3-tier routing for LLM calls.

Tiers:
- fast: Low-latency, cost-efficient (entity extraction, parameter filling)
- standard: Balanced (code generation, report writing)
- reasoning: High-quality (complex analysis, FP reasoning)

No Pydantic — plain dicts only.
"""

import os

# Per-tier LiteLLM model names (Sprint 5: multi-provider fallback)
MODEL_TIERS = {
    "fast": {
        "model": "hydra-fast",
        "max_tokens": 1024,
        "temperature": 0.1,
        "description": "Low-latency tasks: entity extraction, parameter filling, memory synthesis",
    },
    "standard": {
        "model": "hydra-standard",
        "max_tokens": 4096,
        "temperature": 0.3,
        "description": "Balanced tasks: code generation, report writing, synthetic investigations",
    },
    "reasoning": {
        "model": "hydra-reasoning",
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
    "diagnose_failure": "reasoning",
    "generate_patch": "reasoning",
    # Sprint 5 activities
    "validate_generated_code": "fast",
    "enrich_alert_with_memory": "fast",
    # Sprint 9B activities
    "semantic_search": "fast",
    "batch_embed_entities": "fast",
    "re_embed_stale": "fast",
    "compute_eval_metrics": "standard",
    "correlate_alerts": "fast",
    "ingest_threat_feed": "fast",
}


def get_tier_config(activity_name: str) -> dict:
    """Get model config for an activity.

    Returns dict with: model, max_tokens, temperature, tier
    """
    tier_name = ACTIVITY_TIER_MAP.get(activity_name, "fast")
    config = MODEL_TIERS[tier_name].copy()
    config["tier"] = tier_name
    # Allow env override for model (only if explicitly set, not empty)
    env_model = os.environ.get("HYDRA_LLM_MODEL", "").strip()
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
