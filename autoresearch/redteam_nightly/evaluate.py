#!/usr/bin/env python3
"""
Red Team Nightly — immutable harness for evaluating Zovark pipeline robustness.

Loads attack vectors, tests input sanitization and tool execution,
detects bypasses, and reports findings.
"""

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

# Add project root and worker/tools to path so worker imports resolve
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "worker"))

from worker.stages.input_sanitizer import sanitize_siem_event
from worker.tools.runner import execute_plan


ATTACK_VECTORS_PATH = Path(__file__).parent / "attack_vectors.json"
BYPASSES_DIR = Path(__file__).parent / "bypasses"
RESULTS_PATH = Path(__file__).parent / "results.jsonl"

# Representative investigation plan with extraction + brute-force scoring
BRUTE_FORCE_PLAN = [
    {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
    {"tool": "extract_ipv6", "args": {"text": "$raw_log"}},
    {"tool": "extract_domains", "args": {"text": "$raw_log"}},
    {"tool": "extract_urls", "args": {"text": "$raw_log"}},
    {"tool": "extract_usernames", "args": {"text": "$raw_log"}},
    {
        "tool": "score_brute_force",
        "args": {
            "failed_count": "$siem_event.failed_count",
            "unique_sources": "$siem_event.unique_sources",
            "timespan_minutes": "$siem_event.timespan_minutes",
        },
    },
    {
        "tool": "score_generic",
        "args": {
            "indicators_found": "$step1.count",
            "high_severity_count": "$siem_event.unique_sources",
            "medium_severity_count": 0,
        },
    },
]

VERDICT_SEVERITY = {
    "benign": 0,
    "inconclusive": 1,
    "suspicious": 2,
    "true_positive": 3,
}


def _ensure_dirs() -> None:
    BYPASSES_DIR.mkdir(parents=True, exist_ok=True)


def _load_attack_vectors() -> list:
    with open(ATTACK_VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _flatten_sanitized(event: dict) -> str:
    """Flatten all string values in a sanitized event for scanning."""
    parts = []
    for v in event.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.append(_flatten_sanitized(v))
    return " ".join(parts)


def _check_sanitizer_bypass(sanitized_event: dict, bypass_indicators: list) -> list:
    """Return list of indicators that survived sanitization."""
    flat = _flatten_sanitized(sanitized_event)
    survived = []
    for indicator in bypass_indicators:
        if indicator in flat:
            survived.append(indicator)
    return survived


def _check_phantom_iocs(result: dict, phantom_iocs: list) -> list:
    """Return phantom IOC values that incorrectly appeared in output."""
    found = []
    result_iocs = result.get("iocs", [])
    result_values = {str(ioc.get("value", "")) for ioc in result_iocs if isinstance(ioc, dict)}
    result_values.update(str(i) for i in result_iocs if not isinstance(i, dict))
    for phantom in phantom_iocs:
        if phantom in result_values:
            found.append(phantom)
    return found


def _check_missing_extractions(result: dict, must_extract: list) -> list:
    """Return must_extract items that were not found in findings or IOCs."""
    missing = []
    all_texts = []

    for ioc in result.get("iocs", []):
        if isinstance(ioc, dict):
            all_texts.append(str(ioc.get("value", "")))
            for ref in ioc.get("evidence_refs", []):
                all_texts.append(str(ref.get("raw_text", "")))
        else:
            all_texts.append(str(ioc))

    for finding in result.get("findings", []):
        all_texts.append(str(finding))

    corpus = " ".join(all_texts)
    for item in must_extract:
        if item not in corpus:
            missing.append(item)
    return missing


def _check_risk_suppression(result: dict, expected_risk_min: int) -> bool:
    actual = result.get("risk_score", 0)
    return actual < expected_risk_min


def _check_verdict_manipulation(result: dict, expected_verdict: str) -> bool:
    actual = result.get("verdict", "benign")
    return VERDICT_SEVERITY.get(actual, 0) < VERDICT_SEVERITY.get(expected_verdict, 0)


def _run_attack(vector: dict) -> dict:
    """Execute a single attack vector and return bypass report."""
    name = vector["name"]
    category = vector.get("category", "unknown")
    event = vector.get("siem_event", {})
    bypass_indicators = vector.get("bypass_indicators", [])
    phantom_iocs = vector.get("phantom_iocs", [])
    must_extract = vector.get("must_extract", [])
    expected_verdict = vector.get("expected_verdict")
    expected_risk_min = vector.get("expected_risk_min")

    report = {
        "name": name,
        "category": category,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "bypasses": [],
        "sanitizer": {},
        "runner": {},
        "errors": [],
    }

    # --- Stage A: Input Sanitizer ---
    try:
        sanitized = sanitize_siem_event(event)
        report["sanitizer"]["output"] = sanitized
        survived = _check_sanitizer_bypass(sanitized, bypass_indicators)
        if survived:
            report["bypasses"].append({
                "type": "sanitizer_bypass",
                "details": f"Indicators survived sanitization: {survived}",
                "survived": survived,
            })
    except Exception as exc:
        report["errors"].append(f"Sanitizer exception: {str(exc)[:500]}")
        report["errors"].append(traceback.format_exc())
        sanitized = event  # Fall through to runner with original event

    # --- Stage B: Tool Runner ---
    try:
        result = execute_plan(
            plan=BRUTE_FORCE_PLAN,
            siem_event=sanitized,
            history_context={},
            institutional_knowledge={},
            total_timeout=30.0,
            per_tool_timeout=5.0,
            task_id=f"redteam-{name.replace(' ', '-')}",
            tenant_id="redteam",
            trace_id="nightly",
        )
        report["runner"]["output"] = result

        # Phantom IOCs
        phantoms = _check_phantom_iocs(result, phantom_iocs)
        if phantoms:
            report["bypasses"].append({
                "type": "phantom_iocs",
                "details": f"Fabricated IOCs extracted: {phantoms}",
                "phantoms": phantoms,
            })

        # Missing extractions
        missing = _check_missing_extractions(result, must_extract)
        if missing:
            report["bypasses"].append({
                "type": "missing_extraction",
                "details": f"Required extractions missing: {missing}",
                "missing": missing,
            })

        # Risk suppression
        if expected_risk_min is not None and _check_risk_suppression(result, expected_risk_min):
            report["bypasses"].append({
                "type": "risk_suppression",
                "details": (
                    f"Risk score {result.get('risk_score')} below minimum {expected_risk_min}"
                ),
                "actual_risk": result.get("risk_score"),
                "expected_risk_min": expected_risk_min,
            })

        # Verdict manipulation
        if expected_verdict is not None and _check_verdict_manipulation(result, expected_verdict):
            report["bypasses"].append({
                "type": "verdict_manipulation",
                "details": (
                    f"Verdict '{result.get('verdict')}' is less severe than expected '{expected_verdict}'"
                ),
                "actual_verdict": result.get("verdict"),
                "expected_verdict": expected_verdict,
            })

    except Exception as exc:
        report["errors"].append(f"Runner exception: {str(exc)[:500]}")
        report["errors"].append(traceback.format_exc())

    return report


def _save_bypass_report(report: dict) -> None:
    if not report["bypasses"]:
        return
    filename = report["name"].replace(" ", "_").replace("/", "_") + ".json"
    path = BYPASSES_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def _append_result(summary: dict) -> None:
    with open(RESULTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(summary, ensure_ascii=False) + "\n")


def main() -> int:
    _ensure_dirs()
    vectors = _load_attack_vectors()
    total = len(vectors)
    bypass_count = 0
    bypass_reports = []

    print(f"\n{'='*60}")
    print(f"Red Team Nightly — Evaluating {total} attack vectors")
    print(f"{'='*60}\n")

    for idx, vector in enumerate(vectors, 1):
        name = vector["name"]
        print(f"[{idx}/{total}] Testing: {name} ...", end=" ")

        report = _run_attack(vector)
        has_bypass = bool(report["bypasses"])
        has_error = bool(report["errors"])

        if has_bypass:
            bypass_count += 1
            bypass_reports.append(report)
            _save_bypass_report(report)
            print("BYPASS")
            for b in report["bypasses"]:
                detail = b['details'].encode(sys.stdout.encoding or 'utf-8', 'replace').decode(sys.stdout.encoding or 'utf-8')
                print(f"    -> {b['type']}: {detail}")
        elif has_error:
            print("ERROR")
            for e in report["errors"]:
                err = e[:200].encode(sys.stdout.encoding or 'utf-8', 'replace').decode(sys.stdout.encoding or 'utf-8')
                print(f"    -> {err}")
        else:
            print("PASS")

        summary = {
            "timestamp": report["timestamp"],
            "name": name,
            "category": vector.get("category", "unknown"),
            "bypass": has_bypass,
            "bypass_types": [b["type"] for b in report["bypasses"]],
            "error": has_error,
            "error_count": len(report["errors"]),
        }
        _append_result(summary)

    print(f"\n{'='*60}")
    print(f"Results: {bypass_count}/{total} vectors produced bypasses")
    print(f"{'='*60}\n")

    if bypass_reports:
        print("Bypass summary:")
        for report in bypass_reports:
            name_safe = report['name'].encode(sys.stdout.encoding or 'utf-8', 'replace').decode(sys.stdout.encoding or 'utf-8')
            print(f"  * {name_safe}")
            for b in report["bypasses"]:
                detail = b['details'].encode(sys.stdout.encoding or 'utf-8', 'replace').decode(sys.stdout.encoding or 'utf-8')
                print(f"      - {b['type']}: {detail}")
        print(f"\nDetailed reports saved to: {BYPASSES_DIR}")

    print(f"Results log: {RESULTS_PATH}")
    return 0 if bypass_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
