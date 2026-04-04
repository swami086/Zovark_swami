"""
Immutable evaluation harness for AutoResearch Program 2: Tool Selection Prompt Optimization.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MODEL = "llama3.2:3b"
LLM_URLS = [
    "http://zovark-inference:8080",
    "http://zovark-inference:8080",
]
PROMPT_FILE = Path("current_prompt.txt")
TEST_ALERTS_FILE = Path("test_alerts_fast.json")
RESULTS_FILE = Path("results.jsonl")
APPROVED_DIR = Path("approved")
FITNESS_THRESHOLD = 0.95

# All known tool names for fallback text matching
KNOWN_TOOLS = {
    "check_base64",
    "calculate_entropy",
    "correlate_with_history",
    "count_pattern",
    "detect_c2",
    "detect_data_exfil",
    "detect_encoding",
    "detect_golden_ticket",
    "detect_kerberoasting",
    "detect_lolbin_abuse",
    "detect_phishing",
    "detect_ransomware",
    "extract_cves",
    "extract_domains",
    "extract_emails",
    "extract_hashes",
    "extract_ipv4",
    "extract_ipv6",
    "extract_urls",
    "extract_usernames",
    "lookup_institutional_knowledge",
    "lookup_known_bad",
    "map_mitre",
    "parse_auth_log",
    "parse_dns_query",
    "parse_http_request",
    "parse_syslog",
    "parse_windows_event",
    "score_brute_force",
    "score_c2_beacon",
    "score_exfiltration",
    "score_generic",
    "score_lateral_movement",
    "score_phishing",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_llm_base_url() -> str:
    for url in LLM_URLS:
        try:
            r = httpx.get(f"{url}/api/tags", timeout=5.0)
            if r.status_code == 200:
                print(f"[INFO] LLM reachable at {url}")
                return url
        except Exception as exc:
            print(f"[WARN] Could not reach {url}: {exc}")
    raise RuntimeError("LLM is not reachable at any configured URL.")


def chat(client: httpx.Client, base_url: str, system: str, user: str) -> str:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0.0},
    }
    r = client.post(f"{base_url}/api/chat", json=payload, timeout=120.0)
    r.raise_for_status()
    data = r.json()
    return data.get("message", {}).get("content", "")


def parse_tools_from_response(text: str) -> list[str]:
    """Extract tool names from LLM response."""
    # 1. Try strict JSON parsing
    try:
        obj = json.loads(text)
        steps = obj.get("steps", [])
        if isinstance(steps, list):
            return [step["tool"] for step in steps if isinstance(step, dict) and "tool" in step]
    except Exception:
        pass

    # 2. Try to find JSON inside markdown fences
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence_match:
        try:
            obj = json.loads(fence_match.group(1))
            steps = obj.get("steps", [])
            if isinstance(steps, list):
                return [step["tool"] for step in steps if isinstance(step, dict) and "tool" in step]
        except Exception:
            pass

    # 3. Fallback: text matching against known tool names
    found = set()
    lower_text = text.lower()
    for tool in KNOWN_TOOLS:
        # Match whole-word or quoted tool names
        pattern = rf'\b{re.escape(tool)}\b'
        if re.search(pattern, lower_text):
            found.add(tool)
    return sorted(found)


def jaccard(a: list[str], b: list[str]) -> float:
    set_a = set(a)
    set_b = set(b)
    union = set_a | set_b
    if not union:
        return 1.0
    return len(set_a & set_b) / len(union)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if not PROMPT_FILE.exists():
        print(f"[ERROR] Prompt file not found: {PROMPT_FILE}")
        return 1
    if not TEST_ALERTS_FILE.exists():
        print(f"[ERROR] Test alerts file not found: {TEST_ALERTS_FILE}")
        return 1

    system_prompt = PROMPT_FILE.read_text(encoding="utf-8")
    test_alerts = json.loads(TEST_ALERTS_FILE.read_text(encoding="utf-8"))
    print(f"[INFO] Loaded {len(test_alerts)} test alerts.")

    base_url = find_llm_base_url()
    client = httpx.Client()

    scores: list[float] = []
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    results_fp = RESULTS_FILE.open("a", encoding="utf-8")

    for idx, case in enumerate(test_alerts, start=1):
        siem_event = case["siem_event"]
        expected_tools = case["expected_tools"]
        task_type = siem_event.get("task_type", "unknown")
        alert_id = siem_event.get("alert_id", f"#{idx}")

        print(f"\n[{idx}/{len(test_alerts)}] Evaluating {alert_id} ({task_type}) ...")

        try:
            response_text = chat(client, base_url, system_prompt, json.dumps(siem_event, indent=2))
        except Exception as exc:
            print(f"[ERROR] LLM call failed: {exc}")
            response_text = ""

        selected_tools = parse_tools_from_response(response_text)
        similarity = jaccard(selected_tools, expected_tools)
        scores.append(similarity)

        print(f"  Expected : {expected_tools}")
        print(f"  Selected : {selected_tools}")
        print(f"  Jaccard  : {similarity:.4f}")

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "task_type": task_type,
            "expected_tools": expected_tools,
            "selected_tools": selected_tools,
            "jaccard": similarity,
            "raw_response": response_text,
        }
        results_fp.write(json.dumps(record) + "\n")
        results_fp.flush()

    results_fp.close()
    client.close()

    fitness = sum(scores) / len(scores) if scores else 0.0
    print(f"\n{'='*60}")
    print(f"Fitness (avg Jaccard) = {fitness:.4f}")
    print(f"{'='*60}")

    if fitness >= FITNESS_THRESHOLD:
        APPROVED_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        approved_path = APPROVED_DIR / f"prompt_{ts}_fitness{fitness:.4f}.txt"
        approved_path.write_text(system_prompt, encoding="utf-8")
        print(f"[APPROVED] Prompt saved to {approved_path}")
    else:
        print(f"[REJECT] Fitness {fitness:.4f} < threshold {FITNESS_THRESHOLD}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
