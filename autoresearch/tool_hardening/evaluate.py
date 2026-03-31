"""Immutable evaluation harness for tool hardening."""
import json
import sys
import os
import traceback
import io
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 stdout on Windows to avoid UnicodeEncodeError
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", line_buffering=True)

# Add worker/ to path so we can import the real tools as fallback
WORKER_DIR = Path(__file__).resolve().parent.parent.parent / "worker"
if str(WORKER_DIR) not in sys.path:
    sys.path.insert(0, str(WORKER_DIR))

import current_tool

EDGE_CASES_PATH = Path(__file__).with_name("edge_cases.json")
RESULTS_PATH = Path(__file__).with_name("results.jsonl")
IMPROVED_DIR = Path(__file__).with_name("improved")


def _load_edge_cases():
    with open(EDGE_CASES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _check(output, checks):
    """Validate output against check criteria. Returns list of error strings."""
    errors = []

    if "expected_output" in checks:
        if output != checks["expected_output"]:
            errors.append(f"expected_output mismatch: got {output!r}, want {checks['expected_output']!r}")

    if "expected_output_count" in checks:
        try:
            count = len(output)
        except Exception:
            count = None
        if count != checks["expected_output_count"]:
            errors.append(f"expected_output_count mismatch: got {count}, want {checks['expected_output_count']}")

    if "expected_min" in checks:
        if not isinstance(output, (int, float)):
            errors.append(f"expected_min requires numeric output, got {type(output).__name__}")
        elif output < checks["expected_min"]:
            errors.append(f"expected_min violation: {output} < {checks['expected_min']}")

    if "expected_max" in checks:
        if not isinstance(output, (int, float)):
            errors.append(f"expected_max requires numeric output, got {type(output).__name__}")
        elif output > checks["expected_max"]:
            errors.append(f"expected_max violation: {output} > {checks['expected_max']}")

    if "must_contain" in checks:
        target = checks["must_contain"]
        if isinstance(output, list):
            if isinstance(target, list):
                for item in target:
                    if not _list_contains_dict_like(output, item):
                        errors.append(f"must_contain missing item: {item!r}")
            elif isinstance(target, dict):
                if not _list_contains_dict_like(output, target):
                    errors.append(f"must_contain missing dict: {target!r}")
            else:
                if target not in output:
                    errors.append(f"must_contain missing: {target!r}")
        elif isinstance(output, dict):
            if isinstance(target, dict):
                for k, v in target.items():
                    if k not in output or output[k] != v:
                        errors.append(f"must_contain missing key/value: {k}={v!r}")
            else:
                if target not in output.values() and target not in output:
                    errors.append(f"must_contain missing: {target!r}")
        elif isinstance(output, str):
            if isinstance(target, dict):
                for k, v in target.items():
                    if str(v) not in output:
                        errors.append(f"must_contain missing substring: {v!r}")
            elif isinstance(target, list):
                for item in target:
                    if str(item) not in output:
                        errors.append(f"must_contain missing substring: {item!r}")
            else:
                if str(target) not in output:
                    errors.append(f"must_contain missing substring: {target!r}")
        else:
            errors.append(f"must_contain unsupported output type: {type(output).__name__}")

    if "must_not_contain" in checks:
        target = checks["must_not_contain"]
        if isinstance(output, list):
            if isinstance(target, list):
                for item in target:
                    if _list_contains_dict_like(output, item):
                        errors.append(f"must_not_contain found item: {item!r}")
            elif isinstance(target, dict):
                if _list_contains_dict_like(output, target):
                    errors.append(f"must_not_contain found dict: {target!r}")
            else:
                if target in output:
                    errors.append(f"must_not_contain found: {target!r}")
        elif isinstance(output, dict):
            if isinstance(target, dict):
                for k, v in target.items():
                    if k in output and output[k] == v:
                        errors.append(f"must_not_contain found key/value: {k}={v!r}")
            else:
                if target in output.values() or target in output:
                    errors.append(f"must_not_contain found: {target!r}")
        elif isinstance(output, str):
            if isinstance(target, dict):
                for k, v in target.items():
                    if str(v) in output:
                        errors.append(f"must_not_contain found substring: {v!r}")
            elif isinstance(target, list):
                for item in target:
                    if str(item) in output:
                        errors.append(f"must_not_contain found substring: {item!r}")
            else:
                if str(target) in output:
                    errors.append(f"must_not_contain found substring: {target!r}")
        else:
            errors.append(f"must_not_contain unsupported output type: {type(output).__name__}")

    return errors


def _list_contains_dict_like(lst, item):
    """Check if a list contains a dict that is a superset of item (or exact match for non-dict)."""
    if not isinstance(item, dict):
        return item in lst
    for entry in lst:
        if isinstance(entry, dict):
            if all(entry.get(k) == v for k, v in item.items()):
                return True
    return False


def main():
    tool_name = current_tool.TOOL_NAME
    tool_fn = current_tool.tool_function

    all_cases = _load_edge_cases()
    cases = [c for c in all_cases if c["tool"] == tool_name]

    if not cases:
        print(f"No edge cases found for tool: {tool_name}")
        sys.exit(1)

    passed = 0
    failed = 0
    results = []

    for idx, case in enumerate(cases, 1):
        inp = case["input"]
        checks = case.get("checks", {})
        must_not_crash = checks.get("must_not_crash", False)

        try:
            output = tool_fn(**inp)
            crashed = False
            crash_msg = None
        except Exception as exc:
            output = None
            crashed = True
            crash_msg = traceback.format_exc()

        if crashed:
            if must_not_crash:
                errors = []
            else:
                errors = [f"CRASH: {crash_msg}"]
        else:
            errors = _check(output, checks)

        ok = len(errors) == 0
        if ok:
            passed += 1
        else:
            failed += 1

        results.append({
            "case_index": idx,
            "tool": tool_name,
            "input": inp,
            "output": output,
            "passed": ok,
            "errors": errors,
        })

    total = len(cases)
    fitness = passed / total if total else 0.0

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": tool_name,
        "total": total,
        "passed": passed,
        "failed": failed,
        "fitness": round(fitness, 4),
    }

    # Log to results.jsonl
    with open(RESULTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(summary, ensure_ascii=False) + "\n")

    # Print summary
    print(f"Tool: {tool_name}")
    print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Fitness: {fitness:.4f}")

    # Print first few failures for debugging
    for r in results:
        if not r["passed"]:
            print(f"\nFAIL case {r['case_index']}: input={r['input']!r}")
            for err in r["errors"]:
                print(f"  - {err}")

    # Save to improved/ if fitness >= 0.95 and failed == 0
    if fitness >= 0.95 and failed == 0:
        IMPROVED_DIR.mkdir(exist_ok=True)
        out_path = IMPROVED_DIR / f"{tool_name}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "tool": tool_name,
                "fitness": fitness,
                "passed": passed,
                "total": total,
                "timestamp": summary["timestamp"],
            }, f, indent=2, ensure_ascii=False)
        print(f"Saved to {out_path}")

    sys.exit(0 if (fitness >= 0.95 and failed == 0) else 1)


if __name__ == "__main__":
    main()
