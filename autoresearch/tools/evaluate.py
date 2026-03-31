"""
IMMUTABLE evaluation harness for tool AutoResearch.
Tests current_tool.py against tool_specs.json.
Fitness = 0.8 * accuracy + 0.2 * speed_score
Hard constraint: any failure -> fitness capped at 0.79
Approval threshold: fitness >= 0.95 AND 0 failures -> saved to approved/
"""
import json
import time
import os
import sys
import shutil
import importlib
from pathlib import Path

SPEC_PATH = Path(__file__).parent.parent.parent / "worker" / "tools" / "tool_specs.json"
APPROVED_DIR = Path(__file__).parent / "approved"
RESULTS_PATH = Path(__file__).parent / "results.jsonl"

APPROVED_DIR.mkdir(exist_ok=True)


def load_specs():
    with open(SPEC_PATH) as f:
        return json.load(f)


def evaluate_tool(tool_name: str, tool_func, test_cases: list) -> dict:
    """Evaluate a single tool against its test cases."""
    passed = 0
    failed = 0
    errors = []
    total_time = 0.0

    for i, tc in enumerate(test_cases):
        try:
            start = time.perf_counter()
            result = tool_func(**tc["input"])
            elapsed = time.perf_counter() - start
            total_time += elapsed

            ok = True

            # exact match
            if "expected_output" in tc:
                if result != tc["expected_output"]:
                    ok = False
                    errors.append(f"  Case {i}: expected {tc['expected_output']}, got {result}")

            # list length
            if "expected_output_count" in tc:
                actual_len = len(result) if isinstance(result, (list, dict)) else 0
                if actual_len != tc["expected_output_count"]:
                    ok = False
                    errors.append(f"  Case {i}: expected count {tc['expected_output_count']}, got {actual_len}")

            # must contain values
            if "must_contain_values" in tc:
                if isinstance(result, list):
                    result_values = []
                    for item in result:
                        if isinstance(item, dict):
                            result_values.append(item.get("value", ""))
                        else:
                            result_values.append(str(item))
                    for v in tc["must_contain_values"]:
                        if v not in result_values:
                            ok = False
                            errors.append(f"  Case {i}: missing value '{v}' in {result_values}")

            # expected keys
            if "expected_keys" in tc:
                if isinstance(result, dict):
                    for k in tc["expected_keys"]:
                        if k not in result:
                            ok = False
                            errors.append(f"  Case {i}: missing key '{k}'")

            # expected values
            if "expected_values" in tc:
                if isinstance(result, dict):
                    for k, v in tc["expected_values"].items():
                        if result.get(k) != v:
                            ok = False
                            errors.append(f"  Case {i}: {k}={result.get(k)}, expected {v}")

            # numeric range
            if "expected_min" in tc:
                val = result if isinstance(result, (int, float)) else 0
                if val < tc["expected_min"]:
                    ok = False
                    errors.append(f"  Case {i}: {val} < min {tc['expected_min']}")
            if "expected_max" in tc:
                val = result if isinstance(result, (int, float)) else 0
                if val > tc["expected_max"]:
                    ok = False
                    errors.append(f"  Case {i}: {val} > max {tc['expected_max']}")

            # risk range (nested dict)
            if "expected_risk_min" in tc:
                risk = result.get("risk_score", 0) if isinstance(result, dict) else 0
                if risk < tc["expected_risk_min"]:
                    ok = False
                    errors.append(f"  Case {i}: risk {risk} < min {tc['expected_risk_min']}")
            if "expected_risk_max" in tc:
                risk = result.get("risk_score", 0) if isinstance(result, dict) else 0
                if risk > tc["expected_risk_max"]:
                    ok = False
                    errors.append(f"  Case {i}: risk {risk} > max {tc['expected_risk_max']}")

            # must contain IOCs
            if "must_contain_iocs" in tc:
                iocs = result.get("iocs", []) if isinstance(result, dict) else []
                ioc_values = [ioc.get("value", "") if isinstance(ioc, dict) else str(ioc) for ioc in iocs]
                for v in tc["must_contain_iocs"]:
                    if v not in ioc_values:
                        ok = False
                        errors.append(f"  Case {i}: missing IOC '{v}' in {ioc_values[:5]}")

            if ok:
                passed += 1
            else:
                failed += 1

        except Exception as e:
            failed += 1
            errors.append(f"  Case {i}: EXCEPTION: {e}")

    # Calculate fitness
    total = passed + failed
    accuracy = passed / total if total > 0 else 0
    avg_time_ms = (total_time / total * 1000) if total > 0 else 0
    speed_score = max(0, 1.0 - (avg_time_ms / 100)) if avg_time_ms <= 100 else 0

    fitness = 0.8 * accuracy + 0.2 * speed_score
    if failed > 0:
        fitness = min(fitness, 0.79)

    return {
        "tool_name": tool_name,
        "passed": passed,
        "failed": failed,
        "total": total,
        "accuracy": round(accuracy, 4),
        "avg_time_ms": round(avg_time_ms, 2),
        "speed_score": round(speed_score, 4),
        "fitness": round(fitness, 4),
        "errors": errors,
    }


def main():
    """Evaluate current_tool.py against specs."""
    # Import current tool
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        if "current_tool" in sys.modules:
            importlib.reload(sys.modules["current_tool"])
        import current_tool
    except ImportError:
        print("ERROR: current_tool.py not found")
        return

    tool_name = getattr(current_tool, "TOOL_NAME", "unknown")
    tool_func = getattr(current_tool, "tool_function", None)

    if not tool_func:
        print(f"ERROR: {tool_name} has no tool_function")
        return

    specs = load_specs()
    if tool_name not in specs:
        print(f"ERROR: {tool_name} not in tool_specs.json")
        return

    spec = specs[tool_name]
    test_cases = spec.get("test_cases", [])

    result = evaluate_tool(tool_name, tool_func, test_cases)

    # Print results
    print(f"\n{'='*50}")
    print(f"Tool: {tool_name}")
    print(f"Passed: {result['passed']}/{result['total']}")
    print(f"Accuracy: {result['accuracy']}")
    print(f"Avg time: {result['avg_time_ms']}ms")
    print(f"Fitness: {result['fitness']}")
    if result["errors"]:
        print("Errors:")
        for e in result["errors"]:
            print(e)

    # Approve if fitness >= 0.95 and 0 failures
    if result["fitness"] >= 0.95 and result["failed"] == 0:
        dest = APPROVED_DIR / f"{tool_name}.py"
        src = Path(__file__).parent / "current_tool.py"
        shutil.copy(src, dest)
        print(f"APPROVED -> {dest}")
    else:
        print(f"NOT APPROVED (need fitness >= 0.95, 0 failures)")

    # Append to results
    with open(RESULTS_PATH, "a") as f:
        log_entry = {k: v for k, v in result.items() if k != "errors"}
        log_entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        f.write(json.dumps(log_entry) + "\n")

    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
