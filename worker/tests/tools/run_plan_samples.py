#!/usr/bin/env python3
"""Deterministic samples: run a few investigation plans via tools.runner.

Run from repo root (paths resolve from this file):
    cd worker && python tests/tools/run_plan_samples.py

Or: make plan-samples
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_WORKER_ROOT = Path(__file__).resolve().parents[2]
_PLANS_PATH = _WORKER_ROOT / "tools" / "investigation_plans.json"


def main() -> None:
    sys.path.insert(0, str(_WORKER_ROOT))
    from tools.runner import execute_plan

    with open(_PLANS_PATH, encoding="utf-8") as f:
        plans = json.load(f)

    # Lateral movement
    plan = plans["lateral_movement_detection"]["plan"]
    siem = {
        "source_ip": "10.0.0.1",
        "username": "admin",
        "raw_log": (
            "psexec connecting to \\ADMIN$ remote execution "
            "pass-the-hash admin share"
        ),
        "failed_count": 10,
        "unique_sources": 1,
        "timespan_minutes": 10,
    }
    result = execute_plan(plan, siem, {}, {})
    print(
        f"lateral_movement_detection: {result['risk_score']} {result['verdict']}"
    )

    # Phishing
    plan = plans["phishing_investigation"]["plan"]
    siem = {
        "source_ip": "10.0.0.1",
        "username": "admin",
        "raw_log": (
            "From: security@secure-login-update.com Subject: Urgent verify your "
            "account before suspend click here secure login password credential"
        ),
        "failed_count": 10,
        "unique_sources": 1,
        "timespan_minutes": 10,
    }
    result = execute_plan(plan, siem, {}, {})
    print(f"phishing_investigation: {result['risk_score']} {result['verdict']}")
    for f in result.get("findings", []):
        print(f"  finding: {f}")
    for i in result.get("iocs", []):
        print(f"  ioc: {i}")


if __name__ == "__main__":
    main()
