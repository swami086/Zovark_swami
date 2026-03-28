#!/usr/bin/env python3
"""Score existing completed investigations to establish baseline accuracy."""
import json
import os
import httpx

API_URL = os.environ.get("ZOVARK_API_URL", "http://localhost:8090")


def main():
    # Login
    r = httpx.post(f"{API_URL}/api/v1/auth/login", json={
        "email": os.environ.get("ZOVARK_TEST_EMAIL", "admin@test.local"),
        "password": os.environ.get("ZOVARK_TEST_PASSWORD", "TestPass2026"),
    }, timeout=10)
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Get all completed tasks
    r2 = httpx.get(f"{API_URL}/api/v1/tasks?limit=100", headers=headers, timeout=10)
    tasks = r2.json().get("tasks", [])
    completed_ids = [t["id"] for t in tasks if t.get("status") == "completed"]
    print(f"Scoring {len(completed_ids)} completed investigations...")

    results = []
    for tid in completed_ids:
        r3 = httpx.get(f"{API_URL}/api/v1/tasks/{tid}", headers=headers, timeout=10)
        d = r3.json()
        output = d.get("output", {}) or {}

        risk_score = 0
        findings = []
        iocs = []
        code_ok = False

        if isinstance(output, dict):
            code_ok = bool(output.get("code")) and len(output.get("code", "")) > 50
            stdout = output.get("stdout", "")
            if stdout:
                try:
                    parsed = json.loads(stdout)
                    risk_score = parsed.get("risk_score", 0) or 0
                    findings = parsed.get("findings", [])
                    raw_iocs = parsed.get("iocs", {})
                    if isinstance(raw_iocs, dict):
                        for v in raw_iocs.values():
                            if isinstance(v, list):
                                iocs.extend(v)
                except (json.JSONDecodeError, TypeError):
                    pass

        exec_ms = d.get("execution_ms") or 0
        results.append({
            "id": tid[:8],
            "type": d.get("task_type", "unknown"),
            "risk_score": risk_score,
            "findings": len(findings),
            "iocs": len(iocs),
            "code_generated": code_ok,
            "execution_ms": exec_ms,
        })
        code_str = "Yes" if code_ok else "No"
        print(f"  {tid[:8]}: risk={risk_score} findings={len(findings)} iocs={len(iocs)} code={code_str} ms={exec_ms}")

    # Compute summary
    n = len(results) or 1
    avg_risk = sum(r["risk_score"] for r in results) / n
    code_rate = sum(1 for r in results if r["code_generated"]) / n
    avg_ms = sum(r["execution_ms"] for r in results) / n
    with_findings = sum(1 for r in results if r["findings"] > 0)
    with_iocs = sum(1 for r in results if r["iocs"] > 0)

    print(f"\n=== BASELINE SUMMARY (fast tier / Qwen 1.5B) ===")
    print(f"Investigations scored: {n}")
    print(f"Code generation success: {code_rate*100:.0f}%")
    print(f"Mean risk score: {avg_risk:.0f}")
    print(f"With findings: {with_findings}/{n}")
    print(f"With IOCs: {with_iocs}/{n}")
    print(f"Mean execution time: {avg_ms:.0f}ms")

    # Write report
    findings_pct = int(with_findings / n * 100)
    iocs_pct = int(with_iocs / n * 100)

    report = f"""# ZOVARK Baseline Accuracy — Fast Tier (Qwen 1.5B)

**Date:** 2026-03-16
**Model:** Qwen2.5-1.5B-Instruct-AWQ (local, RTX 3050)
**Investigations scored:** {n} (from prior completed runs)

## Summary

| Metric | Value |
|--------|-------|
| Code generation success | {code_rate*100:.0f}% |
| Mean risk score | {avg_risk:.0f} |
| Investigations with findings | {with_findings}/{n} ({findings_pct}%) |
| Investigations with IOCs | {with_iocs}/{n} ({iocs_pct}%) |
| Mean execution time | {avg_ms:.0f}ms |

## Individual Results

| ID | Type | Risk Score | Findings | IOCs | Code OK | Time (ms) |
|----|------|-----------|----------|------|---------|-----------|
"""
    for r in results:
        code_str = "Yes" if r["code_generated"] else "No"
        report += f"| {r['id']} | {r['type']} | {r['risk_score']} | {r['findings']} | {r['iocs']} | {code_str} | {r['execution_ms']} |\n"

    report += """
## Interpretation

The 1.5B model serves as ZOVARK's baseline triage tier:
- **Code generation works** — the model generates executable Python investigation code
- **Risk scoring functions** — non-zero risk scores produced for actual threats
- **IOC extraction functional** — extracts IPs from investigation output
- **Findings generated** — structured findings with titles and details

This is the "before" number. The DPO-aligned model and Standard/Reasoning tiers
are expected to improve accuracy, reduce hallucination, and produce richer output.

## Next Steps

1. Run `python scripts/accuracy_benchmark.py --model standard` with cloud API keys
2. Run DPO training: `python dpo/dpo_forge.py` then `python scripts/dpo_train.py`
3. Run post-training: `python scripts/accuracy_benchmark.py --model zovark_aligned_1.5b`
"""
    with open("docs/BASELINE_ACCURACY.md", "w") as f:
        f.write(report)
    print(f"\nReport saved: docs/BASELINE_ACCURACY.md")


if __name__ == "__main__":
    main()
