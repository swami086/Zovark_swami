"""Model tiering configuration — 3-tier routing for LLM calls.

Tiers:
- fast: Low-latency, cost-efficient (entity extraction, parameter filling)
- standard: Balanced (code generation, report writing)
- reasoning: High-quality (complex analysis, FP reasoning)

Runtime defaults align with Ticket 8 (OpenAI gpt-4o-mini). Override via ZOVARK_LLM_MODEL / tier envs.
"""

import os

# Per-tier model IDs (OpenAI Chat Completions — gpt-4o-mini)
MODEL_TIERS = {
    "fast": {
        "model": "gpt-4o-mini",
        "max_tokens": 1024,
        "temperature": 0.1,
        "description": "Low-latency tasks: entity extraction, parameter filling, memory synthesis",
    },
    "standard": {
        "model": "gpt-4o-mini",
        "max_tokens": 4096,
        "temperature": 0.3,
        "description": "Balanced tasks: code generation, report writing, synthetic investigations",
    },
    "reasoning": {
        "model": "gpt-4o-mini",
        "max_tokens": 4096,
        "temperature": 0.2,
        "description": "Complex analysis: FP reasoning, deobfuscation, multi-step chains",
    },
}

# Activity → tier mapping
ACTIVITY_TIER_MAP = {
    "extract_entities": "fast",
    "fill_skill_parameters": "fast",
    "write_investigation_memory": "fast",
    "generate_code": "standard",
    "generate_followup_code": "standard",
    "generate_incident_report": "standard",
    "generate_synthetic_investigation": "standard",
    "analyze_false_positive": "reasoning",
    "generate_sigma_rule": "reasoning",
    "diagnose_failure": "reasoning",
    "generate_patch": "reasoning",
    "validate_generated_code": "fast",
    "enrich_alert_with_memory": "fast",
    "semantic_search": "fast",
    "batch_embed_entities": "fast",
    "re_embed_stale": "fast",
    "compute_eval_metrics": "standard",
    "correlate_alerts": "fast",
    "ingest_threat_feed": "fast",
    "generate_recommendation": "standard",
    "coalesced_llm_call": "fast",
}


def get_tier_config(activity_name: str) -> dict:
    """Get model config for an activity.

    Returns dict with: model, max_tokens, temperature, tier
    """
    tier_name = ACTIVITY_TIER_MAP.get(activity_name, "fast")
    config = MODEL_TIERS[tier_name].copy()
    config["tier"] = tier_name
    env_model = os.environ.get("ZOVARK_LLM_MODEL", "").strip()
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
