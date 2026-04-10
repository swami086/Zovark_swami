#!/usr/bin/env python3
"""
Standalone 50-case baseline vs quantized verdict gate (Ticket 5).

Exits 0 only when evaluate_model_pair reports passed=True (zero flips, no errors).
Run after producing a quantized GGUF served under --candidate-model.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Repo root: worker package
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "worker"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Verdict flip gate: baseline vs candidate model (50 reference cases)."
    )
    ap.add_argument(
        "--baseline-model",
        default=os.environ.get("ZOVARK_GATE_BASELINE_MODEL", "fast"),
        help="llama-server model id for baseline (e.g. full-precision alias)",
    )
    ap.add_argument(
        "--candidate-model",
        default=os.environ.get("ZOVARK_GATE_CANDIDATE_MODEL", "fast"),
        help="llama-server model id for quantized / candidate",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Number of reference cases (default 50)",
    )
    args = ap.parse_args()

    from finetuning.evaluator import evaluate_model_pair

    r = evaluate_model_pair(args.baseline_model, args.candidate_model, limit=args.limit)
    flips = r.get("verdict_flips") or []
    errors = r.get("errors") or []
    passed = bool(r.get("passed"))

    print(json.dumps(r, indent=2, default=str))

    if passed:
        print("GATE: PASS")
        sys.exit(0)
    print(
        f"GATE: FAIL flips={len(flips)} errors={len(errors)}",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
