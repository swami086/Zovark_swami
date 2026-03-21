"""
Model Router — selects model config based on severity and task type.
Falls back to LITELLM_URL env var if YAML is missing (backward compat).
"""
import os
import yaml
from pathlib import Path
from typing import Optional

LITELLM_URL = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")

_CONFIG_PATH = Path(__file__).parent / "model_config.yaml"

try:
    with open(_CONFIG_PATH) as f:
        _MODEL_CONFIG = yaml.safe_load(f)
except Exception:
    _MODEL_CONFIG = None


def get_model_config(severity: str = "", task_type: str = "") -> dict:
    """
    Select model config based on severity and task type.

    Priority:
      1. task_type_overrides (if enabled)
      2. severity_overrides
      3. default tier
      4. LITELLM_URL env var fallback

    Returns dict with: name, endpoint, model, max_tokens, temperature, timeout_seconds
    """
    if not _MODEL_CONFIG:
        # Fallback: no config file, use env var
        return {
            "name": "env-fallback",
            "endpoint": LITELLM_URL,
            "api_key": LITELLM_KEY,
            "model": "hydra-standard",
            "max_tokens": 4096,
            "temperature": 0.1,
            "timeout_seconds": 300,
        }

    routing = _MODEL_CONFIG.get("routing", {})
    models = _MODEL_CONFIG.get("models", {})

    # 1. Check task_type_overrides
    tier = None
    task_overrides = routing.get("task_type_overrides", {})
    if task_overrides and task_type in task_overrides:
        tier = task_overrides[task_type]

    # 2. Check severity_overrides
    if not tier:
        severity_overrides = routing.get("severity_overrides", {})
        tier = severity_overrides.get(severity.lower(), None)

    # 3. Default
    if not tier:
        tier = routing.get("default", "standard")

    # Resolve tier to model config
    model = models.get(tier, models.get("standard", {}))
    config = dict(model)  # copy
    config["api_key"] = LITELLM_KEY
    return config
