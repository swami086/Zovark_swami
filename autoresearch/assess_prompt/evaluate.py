#!/usr/bin/env python3
"""
IMMUTABLE EVALUATION HARNESS — Do NOT modify after creation.
Evaluates assess prompt: verdict accuracy AND generation speed.
"""
import json
import time
import re
import os
import sys

import httpx

LLM_URL = os.getenv("LLM_URL", "http://zovark-inference:8080")
if not os.getenv("LLM_URL"):
    try:
        httpx.get("http://zovark-inference:8080/api/tags", timeout=2)
    except Exception:
        LLM_URL = "http://zovark-inference:8080"

MODEL = "llama3.1:8b"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_CASES = json.load(open(os.path.join(SCRIPT_DIR, "test_cases.json"), encoding="utf-8"))


def call_llm(system_prompt: str, user_content: str) -> tuple:
    """Call 8B model, return (response_text, elapsed_seconds)."""
    start = time.time()
    try:
        with httpx.Client(timeout=180) as client:
            resp = client.post(
                f"{LLM_URL}/v1/chat/completions",
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content},
                    ],
                    "temperature": 0.1,
                },
            )
            elapsed = time.time() - start
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return content, elapsed
    except Exception as e:
        return f"ERROR: {e}", time.time() - start


def parse_verdict(text: str) -> dict:
    """Extract verdict and risk_score from LLM response."""
    result = {"verdict": "error", "risk_score": 50}

    # Try JSON extraction first
    try:
        json_match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', text, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            if "verdict" in parsed:
                result["verdict"] = parsed["verdict"]
            if "risk_score" in parsed:
                result["risk_score"] = int(parsed["risk_score"])
            return result
    except Exception:
        pass

    # Fallback: keyword extraction
    text_lower = text.lower()
    for v in ["true_positive", "suspicious", "benign", "needs_manual_review", "inconclusive"]:
        if v in text_lower:
            result["verdict"] = v
            break

    risk_match = re.search(r'risk[_\s]*score["\s:=]*(\d+)', text, re.I)
    if risk_match:
        result["risk_score"] = min(100, max(0, int(risk_match.group(1))))

    return result


def evaluate() -> dict:
    prompt_path = os.path.join(SCRIPT_DIR, "current_prompt.txt")
    prompt_text = open(prompt_path, encoding="utf-8").read()

    correct = 0
    total_time = 0.0
    errors = []
    details = []

    for i, case in enumerate(TEST_CASES):
        try:
            user_content = json.dumps(
                {
                    "tool_outputs": case["tool_outputs"],
                    "siem_event_summary": case.get("siem_event_summary", ""),
                },
                ensure_ascii=False,
            )

            response_text, elapsed = call_llm(prompt_text, user_content)
            total_time += elapsed

            parsed = parse_verdict(response_text)

            verdict_match = parsed["verdict"] == case["expected_verdict"]
            risk_close = abs(parsed["risk_score"] - case["expected_risk"]) <= 15

            if verdict_match and risk_close:
                correct += 1
                details.append({"case": i, "status": "PASS", "elapsed": round(elapsed, 1)})
            else:
                errors.append(
                    f"Case {i} ({case.get('siem_event_summary', 'unknown')}): "
                    f"expected {case['expected_verdict']}/{case['expected_risk']}, "
                    f"got {parsed['verdict']}/{parsed['risk_score']}"
                )
                details.append(
                    {
                        "case": i,
                        "status": "FAIL",
                        "elapsed": round(elapsed, 1),
                        "expected": f"{case['expected_verdict']}/{case['expected_risk']}",
                        "got": f"{parsed['verdict']}/{parsed['risk_score']}",
                    }
                )
        except Exception as e:
            errors.append(f"Case {i}: EXCEPTION {type(e).__name__}: {str(e)[:200]}")
            details.append({"case": i, "status": "ERROR", "error": str(e)[:100]})

    total = len(TEST_CASES)
    accuracy = correct / total if total > 0 else 0
    avg_seconds = total_time / total if total > 0 else 999

    # Speed score: under 5s = 1.0, over 20s = 0.0
    speed_score = max(0.0, min(1.0, (20.0 - avg_seconds) / 15.0))

    # Fitness: 70% accuracy, 30% speed
    fitness = 0.7 * accuracy + 0.3 * speed_score

    # Hard constraint: any accuracy drop = cap fitness
    if correct < total:
        fitness = min(fitness, 0.69 + (0.3 * speed_score))

    result = {
        "fitness": round(fitness, 4),
        "accuracy": round(accuracy, 4),
        "correct": correct,
        "total": total,
        "avg_seconds": round(avg_seconds, 2),
        "speed_score": round(speed_score, 4),
        "errors": errors[:10],
        "prompt_length": len(prompt_text),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # Log result
    results_path = os.path.join(SCRIPT_DIR, "results.jsonl")
    with open(results_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(result) + "\n")

    # Print summary
    print(
        f"Fitness: {result['fitness']:.4f} | Accuracy: {accuracy:.0%} ({correct}/{total}) | "
        f"Speed: {avg_seconds:.1f}s avg | Prompt: {len(prompt_text)} chars"
    )
    for e in errors[:5]:
        print(f"  FAIL: {e}")

    # Save if improved: 100% accuracy AND fitness > previous best
    if correct == total:
        approved_dir = os.path.join(SCRIPT_DIR, "approved")
        os.makedirs(approved_dir, exist_ok=True)

        best_path = os.path.join(approved_dir, "best_fitness.txt")
        prev_best = 0.0
        if os.path.exists(best_path):
            prev_best = float(open(best_path, encoding="utf-8").read().strip())

        if fitness > prev_best:
            import shutil

            shutil.copy(
                prompt_path,
                os.path.join(approved_dir, f"prompt_{fitness:.4f}_{int(time.time())}.txt"),
            )
            with open(best_path, "w", encoding="utf-8") as f:
                f.write(str(fitness))
            print(f"*** NEW BEST: {fitness:.4f} (prev: {prev_best:.4f}) — Saved to approved/ ***")

    return result


if __name__ == "__main__":
    evaluate()
