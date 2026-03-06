"""Prompt registry — SHA256-based version tracking for all LLM prompts.

Each prompt is registered with a name and content. The version is
the first 12 chars of SHA256(content), ensuring version changes
when prompt text changes.

No Pydantic — plain dicts only.
"""

import hashlib

# Global registry: name → {content, version, description}
_REGISTRY = {}


def _compute_version(content: str) -> str:
    """Compute SHA256[:12] version hash for prompt content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]


def register_prompt(name: str, content: str, description: str = "") -> str:
    """Register a prompt and return its version hash.

    Args:
        name: Unique prompt name (e.g., 'code_generation')
        content: Full prompt text
        description: Optional description

    Returns:
        Version hash (SHA256[:12])
    """
    version = _compute_version(content)
    _REGISTRY[name] = {
        "content": content,
        "version": version,
        "description": description,
    }
    return version


def get_prompt(name: str) -> dict:
    """Get a registered prompt.

    Returns:
        Dict with content, version, description. Empty dict if not found.
    """
    return _REGISTRY.get(name, {})


def get_version(name: str) -> str:
    """Get version hash for a prompt. Returns '' if not found."""
    entry = _REGISTRY.get(name)
    return entry["version"] if entry else ""


def get_all_prompts() -> dict:
    """Get all registered prompts. Returns {name: {version, description}}."""
    return {
        name: {"version": entry["version"], "description": entry["description"]}
        for name, entry in _REGISTRY.items()
    }


def prompt_count() -> int:
    """Number of registered prompts."""
    return len(_REGISTRY)
