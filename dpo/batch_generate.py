#!/usr/bin/env python3
"""Batch generate chosen DPO examples using llama-server.

Calls qwen2.5:14b for each alert in alert_corpus.json,
runs the generated code, validates output, saves successes.

Usage:
    python dpo/batch_generate.py [--max N] [--resume]

    OLLAMA_URL=http://localhost:11434/v1/chat/completions python dpo/batch_generate.py
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434/v1/chat/completions")
MODEL = os.environ.get("MODEL", "qwen2.5:14b")
CORPUS_PATH = Path("dpo/alert_corpus.json")
OUTPUT_PATH = Path("dpo/chosen_examples.jsonl")
PROGRESS_PATH = Path("dpo/batch_progress.json")

SYSTEM_PROMPT = (
    "You are a senior security analyst. Generate a SHORT, self-contained Python script that: "
    "1. Embeds the SIEM alert data as a string variable. "
    "2. Uses regex to extract ALL IOCs: IP addresses, usernames, hostnames, file hashes (MD5/SHA), file paths, domains, email addresses. "
    "3. Analyzes the events for security findings. "
    "4. Prints valid JSON to stdout with keys: findings (array of {title, details}), "
    "iocs (array of {type, value, confidence}), risk_score (int 0-100), recommendations (array of strings). "
    "IOC types: ipv4, username, hostname, hash_md5, file_path, domain, email. "
    "Use ONLY Python stdlib. Keep it under 80 lines. No input(), no subprocess, no network, no file reads."
)

# Simplified AST prefilter check
BANNED_IMPORTS = {"os", "sys", "subprocess", "socket", "shutil", "ctypes", "multiprocessing"}
BANNED_PATTERNS = [
    r'\bimport\s+(os|sys|subprocess|socket|shutil|ctypes)\b',
    r'\bfrom\s+(os|sys|subprocess|socket)\s+import\b',
    r'\b__import__\b',
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bcompile\s*\(',
]


def is_safe_code(code):
    """Basic AST prefilter — reject dangerous code."""
    for pattern in BANNED_PATTERNS:
        if re.search(pattern, code):
            return False, f"Banned pattern: {pattern}"
    return True, "ok"


def call_llm(system, user_msg):
    """Call llama-server and return content."""
    payload = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg}
        ],
        "temperature": 0.2,
        "max_tokens": 1500,
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    start = time.time()
    with urllib.request.urlopen(req, timeout=900) as resp:
        result = json.loads(resp.read())
    elapsed = time.time() - start

    content = result["choices"][0]["message"]["content"]
    usage = result.get("usage", {})
    return content, elapsed, usage


def extract_code(response):
    """Extract Python code from LLM response."""
    if "```python" in response:
        return response.split("```python")[1].split("```")[0].strip()
    if "```" in response:
        return response.split("```")[1].split("```")[0].strip()
    return response.strip()


def strip_special_tokens(code):
    """Remove LLM special tokens."""
    code = re.sub(r'<[｜|][^>]*[｜|]>', '', code)
    code = re.sub(r'<\|(?:im_start|im_end|endoftext|begin_of_sentence|end_of_sentence)\|>', '', code)
    return code


def run_code(code, timeout=30):
    """Execute code and return output."""
    try:
        r = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1


def score_iocs(found_iocs, expected):
    """Score IOC extraction quality."""
    found_vals = set()
    for ioc in found_iocs:
        if isinstance(ioc, dict):
            found_vals.add(str(ioc.get("value", "")).lower())
    hits = sum(1 for e in expected if e.lower() in found_vals or any(e.lower() in fv for fv in found_vals))
    return hits, len(expected)


def process_alert(alert):
    """Generate and validate code for one alert."""
    siem_json = json.dumps({
        "title": alert["title"],
        "source_ip": alert["source_ip"],
        "destination_ip": alert["destination_ip"],
        "hostname": alert["hostname"],
        "username": alert["username"],
        "rule_name": alert["rule_name"],
        "raw_log": alert["raw_log"],
    }, indent=2)

    user_msg = f"SIEM ALERT:\n{siem_json}\n\nAnalyze this {alert['category']} incident. Extract ALL IOCs. Output JSON."

    # Call LLM
    content, elapsed, usage = call_llm(SYSTEM_PROMPT, user_msg)
    tokens = usage.get("completion_tokens", 0)
    print(f"    LLM: {tokens} tokens in {elapsed:.0f}s", flush=True)

    # Extract and clean code
    code = extract_code(content)
    code = strip_special_tokens(code)

    # Safety check
    safe, reason = is_safe_code(code)
    if not safe:
        return None, f"UNSAFE: {reason}"

    # Execute
    stdout, stderr, rc = run_code(code)
    if rc != 0:
        return None, f"EXEC_FAIL (rc={rc}): {stderr[:150]}"

    # Parse JSON output
    try:
        stdout_clean = stdout.strip()
        if not stdout_clean.startswith("{"):
            idx = stdout_clean.find("{")
            end = stdout_clean.rfind("}")
            if idx >= 0 and end > idx:
                stdout_clean = stdout_clean[idx:end+1]
        output = json.loads(stdout_clean)
    except:
        return None, f"JSON_FAIL: {stdout[:100]}"

    iocs = output.get("iocs", [])
    findings = output.get("findings", [])
    risk = output.get("risk_score", 0)

    # Score
    hits, total = score_iocs(iocs, alert.get("expected_iocs", []))

    return {
        "alert_id": alert["id"],
        "category": alert["category"],
        "task_type": alert["task_type"],
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt": user_msg,
        "generated_code": code,
        "output": output,
        "iocs_matched": hits,
        "iocs_expected": total,
        "findings_count": len(findings),
        "risk_score": risk,
        "tokens": tokens,
        "time_s": round(elapsed, 1),
    }, None


def main():
    max_alerts = int(os.environ.get("MAX_ALERTS", "25"))
    resume = os.environ.get("RESUME", "1") == "1"

    # Load corpus
    with open(CORPUS_PATH) as f:
        alerts = json.load(f)
    alerts = alerts[:max_alerts]

    # Load progress
    completed_ids = set()
    if resume and PROGRESS_PATH.exists():
        with open(PROGRESS_PATH) as f:
            progress = json.load(f)
            completed_ids = set(progress.get("completed", []))
        print(f"Resuming: {len(completed_ids)} already done")

    results = []
    errors = []

    # Load existing results
    if resume and OUTPUT_PATH.exists():
        with open(OUTPUT_PATH) as f:
            for line in f:
                results.append(json.loads(line))

    print(f"Processing {len(alerts)} alerts (model={MODEL})...", flush=True)
    print(f"Estimated time: {len(alerts) * 12}min ({len(alerts) * 12 / 60:.1f}h)\n")

    for i, alert in enumerate(alerts):
        if alert["id"] in completed_ids:
            print(f"[{i+1}/{len(alerts)}] SKIP {alert['id']} ({alert['title'][:40]})")
            continue

        print(f"[{i+1}/{len(alerts)}] {alert['id']} ({alert['title'][:50]})", flush=True)

        try:
            result, error = process_alert(alert)
        except Exception as e:
            error = f"EXCEPTION: {e}"
            result = None

        if result:
            results.append(result)
            completed_ids.add(alert["id"])
            print(f"    OK: {result['iocs_matched']}/{result['iocs_expected']} IOCs, "
                  f"{result['findings_count']} findings, risk {result['risk_score']}", flush=True)

            # Append to output file
            with open(OUTPUT_PATH, "a") as f:
                f.write(json.dumps(result) + "\n")
        else:
            errors.append({"id": alert["id"], "error": error})
            completed_ids.add(alert["id"])  # Don't retry on resume
            print(f"    FAIL: {error}", flush=True)

        # Save progress
        with open(PROGRESS_PATH, "w") as f:
            json.dump({"completed": list(completed_ids), "errors": errors}, f)

    # Summary
    print(f"\n{'='*60}")
    print(f"BATCH GENERATION COMPLETE")
    print(f"  Succeeded: {len(results)}/{len(alerts)}")
    print(f"  Failed: {len(errors)}")
    if results:
        avg_ioc = sum(r["iocs_matched"] for r in results) / len(results)
        avg_risk = sum(r["risk_score"] for r in results) / len(results)
        print(f"  Avg IOC match: {avg_ioc:.1f}")
        print(f"  Avg risk score: {avg_risk:.0f}")
        by_cat = {}
        for r in results:
            cat = r["category"]
            by_cat.setdefault(cat, []).append(r["iocs_matched"])
        print(f"  By category:")
        for cat, scores in sorted(by_cat.items()):
            print(f"    {cat}: {len(scores)} alerts, avg IOC match {sum(scores)/len(scores):.1f}")


if __name__ == "__main__":
    main()
