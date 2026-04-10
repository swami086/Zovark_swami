"""CMMC control hints from MITRE techniques — data driven via config/compliance_rules.yaml."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

import yaml

_RULES_PATH = Path(__file__).resolve().parents[2] / "config" / "compliance_rules.yaml"
_cache: Dict[str, Any] | None = None


def _load_rules() -> Dict[str, Any]:
    global _cache
    if _cache is not None:
        return _cache
    path = os.environ.get("ZOVARK_COMPLIANCE_RULES_PATH", str(_RULES_PATH))
    p = Path(path)
    if not p.is_file():
        _cache = {}
        return _cache
    with open(p, encoding="utf-8") as f:
        _cache = yaml.safe_load(f) or {}
    return _cache


def evaluate_cmmc_for_techniques(technique_ids: List[str]) -> Dict[str, Any]:
    """Return unique CMMC control IDs implied by the given MITRE technique IDs."""
    rules = _load_rules()
    section = rules.get("cmmc") or {}
    mapping = section.get("technique_controls") or {}
    controls: set[str] = set()
    for tid in technique_ids or []:
        key = str(tid).upper() if tid else ""
        for c in mapping.get(key, []) or []:
            controls.add(str(c))
    return {
        "framework": "CMMC",
        "control_ids": sorted(controls),
        "source": "compliance_rules.yaml",
    }
