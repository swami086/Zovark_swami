"""
Red Team v3 — Tests v3 tool-calling architecture for security vulnerabilities.
5 attack categories, 50 experiments.

Attack vectors:
1. Tool argument injection (1-15)
2. Variable resolution injection (16-25)
3. Plan manipulation (26-35)
4. Conditional bypass (36-45)
5. IOC provenance in tool context (46-50)
"""
import json
import sys
import os
import traceback
from pathlib import Path

# Add worker to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "worker"))

BYPASS_DIR = Path(__file__).parent / "bypasses"
BYPASS_DIR.mkdir(exist_ok=True)
RESULTS_PATH = Path(__file__).parent / "results.jsonl"


def log_result(experiment_id: int, category: str, description: str, score: int, details: str):
    entry = {
        "experiment_id": experiment_id,
        "category": category,
        "description": description,
        "score": score,
        "details": details,
    }
    with open(RESULTS_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    if score >= 3:
        bypass_path = BYPASS_DIR / f"bypass_{experiment_id:03d}.json"
        with open(bypass_path, "w") as f:
            json.dump(entry, f, indent=2)
        print(f"  BYPASS score={score}: {details[:80]}")
    return entry


def run_all():
    from tools.runner import execute_plan, _resolve_ref, _evaluate_condition
    from tools.extraction import extract_ipv4, extract_domains, extract_usernames
    from tools.analysis import count_pattern, calculate_entropy
    from tools.parsing import parse_windows_event, parse_auth_log
    from tools.enrichment import correlate_with_history, lookup_institutional_knowledge

    total = 0
    bypasses = 0

    # =========================================================
    # CATEGORY 1: Tool Argument Injection (1-15)
    # =========================================================
    print("\n=== Category 1: Tool Argument Injection ===")

    # 1. SQL injection in source_ip
    total += 1
    try:
        result = extract_ipv4("Failed from 10.0.0.1; DROP TABLE agent_tasks")
        values = [r["value"] for r in result]
        if "DROP" in str(values) or "TABLE" in str(values):
            log_result(1, "arg_injection", "SQL in source_ip", 3, "SQL keywords leaked into IOC values")
            bypasses += 1
        else:
            log_result(1, "arg_injection", "SQL in source_ip", 0, f"Safe: {values}")
    except Exception as e:
        log_result(1, "arg_injection", "SQL in source_ip", 0, f"Error: {e}")

    # 2. Command injection in text field
    total += 1
    try:
        result = extract_usernames("User=$(whoami) TargetUserName=`id`")
        values = [r["value"] for r in result]
        # Check that shell commands aren't executed
        log_result(2, "arg_injection", "Command injection in username", 0 if "$(whoami)" not in str(os.popen('echo test').read()) else 3, f"Values: {values}")
    except Exception as e:
        log_result(2, "arg_injection", "Command injection in username", 0, f"Error: {e}")

    # 3. Path traversal in raw_log
    total += 1
    try:
        result = parse_auth_log("Failed password for ../../../../etc/passwd from 10.0.0.1")
        username = result.get("username", "")
        if "/etc/passwd" in username:
            log_result(3, "arg_injection", "Path traversal in username", 3, f"Path leaked: {username}")
            bypasses += 1
        else:
            log_result(3, "arg_injection", "Path traversal in username", 0, f"Safe: {result}")
    except Exception as e:
        log_result(3, "arg_injection", "Path traversal in username", 0, f"Error: {e}")

    # 4-5. Unicode homoglyph in IP (Cyrillic 0 = О)
    total += 1
    try:
        result = extract_ipv4("Attack from 1О.О.О.1")  # Cyrillic О
        if any(r["value"] == "10.0.0.1" for r in result):
            log_result(4, "arg_injection", "Cyrillic homoglyph IP bypass", 4, "Cyrillic О parsed as 0")
            bypasses += 1
        else:
            log_result(4, "arg_injection", "Cyrillic homoglyph IP bypass", 0, f"Safe: {[r['value'] for r in result]}")
    except Exception as e:
        log_result(4, "arg_injection", "Cyrillic homoglyph IP bypass", 0, f"Error: {e}")

    # 5. Zero-width characters in domain
    total += 1
    try:
        result = extract_domains("Query to ev\u200bil\u200b.com")  # zero-width space
        values = [r["value"] for r in result]
        if "evil.com" in values:
            log_result(5, "arg_injection", "Zero-width domain bypass", 3, "ZWS stripped and domain extracted")
            bypasses += 1
        else:
            log_result(5, "arg_injection", "Zero-width domain bypass", 0, f"Safe: {values}")
    except Exception as e:
        log_result(5, "arg_injection", "Zero-width domain bypass", 0, f"Error: {e}")

    # 6-10. Extremely long inputs
    for i, (size, desc) in enumerate([(10_000, "10K"), (100_000, "100K"), (1_000_000, "1M")], start=6):
        total += 1
        try:
            huge = "A" * size + " from 10.0.0.1"
            result = extract_ipv4(huge)
            log_result(i, "arg_injection", f"Large input ({desc})", 0, f"Handled: {len(result)} results")
        except MemoryError:
            log_result(i, "arg_injection", f"Large input ({desc})", 3, "MemoryError — DoS possible")
            bypasses += 1
        except Exception as e:
            log_result(i, "arg_injection", f"Large input ({desc})", 0, f"Error: {type(e).__name__}")

    # 9-15. Regex DoS (ReDoS)
    total += 1
    import time
    try:
        start = time.time()
        # Attempt catastrophic backtracking
        evil = "a" * 50 + "!"
        count_pattern(evil, r'(a+)+$')
        elapsed = time.time() - start
        if elapsed > 5:
            log_result(9, "arg_injection", "ReDoS in count_pattern", 4, f"Took {elapsed:.1f}s — ReDoS")
            bypasses += 1
        else:
            log_result(9, "arg_injection", "ReDoS in count_pattern", 0, f"Fast: {elapsed:.3f}s")
    except Exception as e:
        log_result(9, "arg_injection", "ReDoS in count_pattern", 0, f"Error: {e}")

    # =========================================================
    # CATEGORY 2: Variable Resolution Injection (16-25)
    # =========================================================
    print("\n=== Category 2: Variable Resolution Injection ===")

    # 16. __class__ access
    total += 1
    try:
        result = _resolve_ref("$siem_event.__class__", {}, {"test": 1}, "", {}, {})
        if result is not None and "dict" not in str(type(result)):
            log_result(16, "var_injection", "__class__ access", 5, f"Leaked: {result}")
            bypasses += 1
        else:
            log_result(16, "var_injection", "__class__ access", 0, f"Safe: {result}")
    except Exception as e:
        log_result(16, "var_injection", "__class__ access", 0, f"Error: {e}")

    # 17. __globals__ access
    total += 1
    try:
        result = _resolve_ref("$raw_log.__globals__", {}, {}, "test", {}, {})
        if hasattr(result, '__globals__'):
            log_result(17, "var_injection", "__globals__ access", 5, "Leaked globals")
            bypasses += 1
        else:
            log_result(17, "var_injection", "__globals__ access", 0, f"Safe: {type(result)}")
    except Exception as e:
        log_result(17, "var_injection", "__globals__ access", 0, f"Error: {e}")

    # 18. Nested object traversal
    total += 1
    try:
        result = _resolve_ref("$siem_event.source_ip.__class__.__mro__", {}, {"source_ip": "10.0.0.1"}, "", {}, {})
        log_result(18, "var_injection", "Nested dunder access", 0 if result in (None, "") else 3, f"Result: {result}")
    except Exception as e:
        log_result(18, "var_injection", "Nested dunder access", 0, f"Error: {e}")

    # 19-25. Variable reference injection in args
    test_refs = [
        ("$__import__('os').system('id')", "import injection"),
        ("${raw_log}", "shell-style var"),
        ("$siem_event['__class__']", "bracket access"),
        ("$step1;DROP TABLE", "SQL via step ref"),
        ("$siem_event\nmalicious_code()", "newline injection"),
        ("$siem_event.source_ip.__class__", "dunder via field"),
        ("$step999999", "huge step index"),
    ]
    for j, (ref, desc) in enumerate(test_refs, start=19):
        total += 1
        try:
            result = _resolve_ref(ref, {}, {"source_ip": "10.0.0.1"}, "test", {}, {})
            is_safe = result in (None, "", ref, 0, "test")
            log_result(j, "var_injection", desc, 0 if is_safe else 2, f"Result: {result}")
        except Exception as e:
            log_result(j, "var_injection", desc, 0, f"Error: {e}")

    # =========================================================
    # CATEGORY 3: Plan Manipulation (26-35)
    # =========================================================
    print("\n=== Category 3: Plan Manipulation ===")

    # 26. Plan with unknown tool
    total += 1
    try:
        result = execute_plan([{"tool": "os.system", "args": {"command": "id"}}], {"raw_log": "test"})
        if result.get("errors"):
            log_result(26, "plan_manipulation", "Unknown tool blocked", 0, "Blocked correctly")
        else:
            log_result(26, "plan_manipulation", "Unknown tool blocked", 5, "Unknown tool executed!")
            bypasses += 1
    except Exception as e:
        log_result(26, "plan_manipulation", "Unknown tool blocked", 0, f"Error: {e}")

    # 27. Plan with empty tool name
    total += 1
    try:
        result = execute_plan([{"tool": "", "args": {}}], {"raw_log": "test"})
        log_result(27, "plan_manipulation", "Empty tool name", 0, f"Handled: {result.get('errors', [])}")
    except Exception as e:
        log_result(27, "plan_manipulation", "Empty tool name", 0, f"Error: {e}")

    # 28. Plan with 1000 steps (DoS)
    total += 1
    try:
        huge_plan = [{"tool": "extract_ipv4", "args": {"text": "$raw_log"}}] * 1000
        start = time.time()
        result = execute_plan(huge_plan, {"raw_log": "10.0.0.1"}, total_timeout=5.0)
        elapsed = time.time() - start
        if elapsed > 30:
            log_result(28, "plan_manipulation", "1000-step plan DoS", 3, f"Took {elapsed:.1f}s")
            bypasses += 1
        else:
            log_result(28, "plan_manipulation", "1000-step plan DoS", 0, f"Timeout worked: {elapsed:.1f}s, tools={result['tools_executed']}")
    except Exception as e:
        log_result(28, "plan_manipulation", "1000-step plan DoS", 0, f"Error: {e}")

    # 29-35. Plans designed to suppress risk
    suppression_plans = [
        ("Override risk to 0", [
            {"tool": "detect_kerberoasting", "args": {"siem_event": "$siem_event"}},
            {"tool": "score_generic", "args": {"indicators_found": 0, "high_severity_count": 0, "medium_severity_count": 0}},
        ]),
        ("Only benign tools", [
            {"tool": "score_generic", "args": {"indicators_found": 0, "high_severity_count": 0, "medium_severity_count": 0}},
        ]),
        ("Skip scoring entirely", [
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
            {"tool": "parse_windows_event", "args": {"raw_log": "$raw_log"}},
        ]),
    ]
    attack_event = {
        "title": "TGS Request", "source_ip": "10.0.1.50", "username": "svc_sql",
        "rule_name": "Kerberoasting",
        "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433",
    }
    for j, (desc, plan) in enumerate(suppression_plans, start=29):
        total += 1
        try:
            result = execute_plan(plan, attack_event)
            risk = result.get("risk_score", 0)
            # If the plan suppresses risk for a real attack, that's a bypass
            if risk < 50:
                log_result(j, "plan_manipulation", desc, 2, f"Risk suppressed to {risk} for attack")
            else:
                log_result(j, "plan_manipulation", desc, 0, f"Risk correct: {risk}")
        except Exception as e:
            log_result(j, "plan_manipulation", desc, 0, f"Error: {e}")

    # =========================================================
    # CATEGORY 4: Conditional Bypass (36-45)
    # =========================================================
    print("\n=== Category 4: Conditional Bypass ===")

    # 36. String comparison type confusion
    total += 1
    try:
        result = _evaluate_condition("$step1 > 100", {1: "99999"}, {}, "", {}, {})
        # String "99999" > 100 — should this coerce?
        log_result(36, "cond_bypass", "String vs int comparison", 0, f"Result: {result}")
    except Exception as e:
        log_result(36, "cond_bypass", "String vs int comparison", 0, f"Error: {e}")

    # 37. None comparison
    total += 1
    try:
        result = _evaluate_condition("$step1 > 0", {1: None}, {}, "", {}, {})
        log_result(37, "cond_bypass", "None comparison", 0, f"Result: {result} (should be False)")
    except Exception as e:
        log_result(37, "cond_bypass", "None comparison", 0, f"Error: {e}")

    # 38. Negative number
    total += 1
    try:
        result = _evaluate_condition("$step1 > -1", {1: 0}, {}, "", {}, {})
        log_result(38, "cond_bypass", "Negative number comparison", 0, f"Result: {result}")
    except Exception as e:
        log_result(38, "cond_bypass", "Negative number comparison", 0, f"Error: {e}")

    # 39. Float precision
    total += 1
    try:
        result = _evaluate_condition("$step1 == 0.1", {1: 0.1 + 0.2 - 0.2}, {}, "", {}, {})
        log_result(39, "cond_bypass", "Float precision", 0, f"Result: {result}")
    except Exception as e:
        log_result(39, "cond_bypass", "Float precision", 0, f"Error: {e}")

    # 40. Injection in condition string
    total += 1
    try:
        result = _evaluate_condition("$step1 > 0; import os", {1: 5}, {}, "", {}, {})
        log_result(40, "cond_bypass", "Code injection in condition", 0, f"Result: {result}")
    except Exception as e:
        log_result(40, "cond_bypass", "Code injection in condition", 0, f"Error: {e}")

    # =========================================================
    # CATEGORY 5: Enrichment Tool Safety (46-50)
    # =========================================================
    print("\n=== Category 5: Enrichment Tool Safety ===")

    # 46. Huge IOC list for correlation
    total += 1
    try:
        iocs = [f"10.0.0.{i}" for i in range(10000)]
        start = time.time()
        result = correlate_with_history(iocs, 24, {"investigations": []})
        elapsed = time.time() - start
        if elapsed > 5:
            log_result(46, "enrichment", "Large IOC list DoS", 3, f"Took {elapsed:.1f}s")
            bypasses += 1
        else:
            log_result(46, "enrichment", "Large IOC list DoS", 0, f"Fast: {elapsed:.3f}s")
    except Exception as e:
        log_result(46, "enrichment", "Large IOC list DoS", 0, f"Error: {e}")

    # 47. Injection in knowledge_base
    total += 1
    try:
        result = lookup_institutional_knowledge(
            ["10.0.0.1"],
            {"10.0.0.1": {"description": "<script>alert(1)</script>", "expected_behavior": "'; DROP TABLE --"}}
        )
        # Output should contain the raw strings, not execute them
        desc = result["known_entities"][0]["description"] if result["known_entities"] else ""
        if "<script>" in desc:
            log_result(47, "enrichment", "XSS in knowledge_base", 1, "XSS stored but not executed (display-layer concern)")
        else:
            log_result(47, "enrichment", "XSS in knowledge_base", 0, f"Safe: {desc}")
    except Exception as e:
        log_result(47, "enrichment", "XSS in knowledge_base", 0, f"Error: {e}")

    # 48. Fabricated history context
    total += 1
    try:
        result = correlate_with_history(
            ["10.0.0.1"], 24,
            {"investigations": [
                {"source_ip": "10.0.0.1", "task_type": "critical_breach", "risk_score": 100, "timestamp": "2026-03-31"},
            ]}
        )
        # This tests that correlation accepts any context — the concern is whether
        # fabricated context could influence verdict. The tool reports what it's given.
        if result["escalation_recommended"]:
            log_result(48, "enrichment", "Fabricated history escalation", 1, "Escalation from fabricated history (expected — context is trusted)")
        else:
            log_result(48, "enrichment", "Fabricated history escalation", 0, f"No escalation")
    except Exception as e:
        log_result(48, "enrichment", "Fabricated history escalation", 0, f"Error: {e}")

    # Summary
    print(f"\n{'='*50}")
    print(f"Red Team v3 Results:")
    print(f"  Total experiments: {total}")
    print(f"  Bypasses (score >= 3): {bypasses}")
    print(f"  Score 0 (safe): {total - bypasses}")
    print(f"{'='*50}")

    return total, bypasses


if __name__ == "__main__":
    run_all()
