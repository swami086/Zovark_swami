"""Score B3-B5 results from raw llama-server JSON responses."""
import json, subprocess, sys, re, os

RESULTS = {}
EXPECTED = {
    "B3": ["10.0.0.200", "185.220.101.99", "PLC-CTRL-01", "deadbeef12345678", "scada_svc"],
    "B4": ["10.0.0.99", "10.0.0.5", "admin", "WEB-PROD-01"],
    "B5": ["10.0.0.50", "10.0.0.200", "svc_backup", "aad3b435b51404eeaad3b435b51404ee", "mimikatz.exe"],
}

for name, path in [("B3", "/results/b3_result.json"), ("B4", "/results/b4_result.json"), ("B5", "/results/b5_result.json")]:
    print(f"\n{'='*60}")
    print(f"TEST: {name}")

    if not os.path.exists(path):
        print(f"  File not found: {path}")
        RESULTS[name] = {"status": "not_run"}
        continue

    try:
        with open(path) as f:
            raw = json.load(f)
    except:
        print(f"  JSON parse failed for {path}")
        RESULTS[name] = {"status": "json_failed"}
        continue

    content = raw["choices"][0]["message"]["content"]
    usage = raw.get("usage", {})
    tokens = usage.get("completion_tokens", 0)
    timings = raw.get("timings", {})
    pred_ms = timings.get("predicted_ms", 0)

    print(f"  Tokens: {tokens}, Time: {pred_ms/1000:.0f}s")

    # Extract code
    if "```python" in content:
        code = content.split("```python")[1].split("```")[0].strip()
    elif "```" in content:
        code = content.split("```")[1].split("```")[0].strip()
    else:
        code = content.strip()

    print(f"  Code: {len(code)} chars, {len(code.split(chr(10)))} lines")

    # Run code
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            print(f"  EXEC FAILED (rc={r.returncode}): {r.stderr[:200]}")
            RESULTS[name] = {"status": "exec_failed", "error": r.stderr[:100], "tokens": tokens, "time_s": pred_ms/1000}
            continue
        stdout = r.stdout.strip()
    except Exception as e:
        print(f"  EXEC ERROR: {e}")
        RESULTS[name] = {"status": "exec_error", "tokens": tokens, "time_s": pred_ms/1000}
        continue

    # Parse output JSON
    try:
        if not stdout.startswith("{"):
            idx = stdout.find("{")
            end = stdout.rfind("}")
            if idx >= 0 and end > idx:
                stdout = stdout[idx:end+1]
        output = json.loads(stdout)
    except:
        print(f"  OUTPUT JSON FAILED: {stdout[:200]}")
        RESULTS[name] = {"status": "json_output_failed", "tokens": tokens, "time_s": pred_ms/1000}
        continue

    findings = output.get("findings", [])
    iocs = output.get("iocs", [])
    risk = output.get("risk_score", 0)

    # Score IOCs
    found_vals = set()
    for ioc in iocs:
        if isinstance(ioc, dict):
            found_vals.add(str(ioc.get("value","")).lower())
        else:
            found_vals.add(str(ioc).lower())

    expected = EXPECTED.get(name, [])
    hits = sum(1 for e in expected if e.lower() in found_vals or any(e.lower() in fv for fv in found_vals))

    print(f"  Findings: {len(findings)}, IOCs: {len(iocs)}, Matched: {hits}/{len(expected)}, Risk: {risk}")
    for ioc in iocs[:10]:
        if isinstance(ioc, dict):
            print(f"    {ioc.get('type','?')}: {ioc.get('value','?')}")

    missed = [e for e in expected if e.lower() not in found_vals and not any(e.lower() in fv for fv in found_vals)]
    if missed:
        print(f"  MISSED: {missed}")

    RESULTS[name] = {
        "status": "completed", "findings": len(findings), "iocs_found": len(iocs),
        "iocs_matched": hits, "iocs_expected": len(expected),
        "risk_score": risk, "tokens": tokens, "time_s": round(pred_ms/1000, 1)
    }

# Summary
print(f"\n{'='*60}")
print("SUMMARY")
for name, r in RESULTS.items():
    s = r.get("status", "?")
    if s == "completed":
        print(f"  {name}: {r['iocs_matched']}/{r['iocs_expected']} IOCs, {r['findings']} findings, risk {r['risk_score']}, {r['time_s']}s")
    else:
        print(f"  {name}: {s}")

# Save
with open("/results/b3_b5_scores.json", "w") as f:
    json.dump(RESULTS, f, indent=2)
print("\nScores saved to /results/b3_b5_scores.json")
