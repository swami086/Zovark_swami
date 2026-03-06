"""Model evaluation framework — measures fine-tuned model quality.

Runs a set of benchmark prompts through the model and scores outputs
against reference investigations.
"""

import os
import json
import time
import httpx
import psycopg2

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
LITELLM_URL = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")


BENCHMARK_PROMPTS = [
    {
        "id": "eval_brute_force",
        "prompt": "Investigate a brute force attack from IP 192.168.1.100 targeting SSH on 10.0.0.5. Check auth logs for failed attempts, identify patterns, and determine if any accounts were compromised.",
        "expected_keywords": ["ssh", "auth", "failed", "login", "brute", "password"],
        "task_type": "brute_force",
    },
    {
        "id": "eval_c2",
        "prompt": "Analyze suspicious DNS queries to randomized subdomains of evil-c2.com from host WORKSTATION-42. Check for beaconing patterns, data exfiltration indicators, and lateral movement.",
        "expected_keywords": ["dns", "beacon", "c2", "command", "control", "exfil"],
        "task_type": "c2",
    },
    {
        "id": "eval_lateral",
        "prompt": "Investigate lateral movement detected: admin account used PsExec to access 5 servers in 2 minutes. Check for credential dumping, privilege escalation, and unauthorized access patterns.",
        "expected_keywords": ["psexec", "lateral", "credential", "privilege", "access"],
        "task_type": "lateral_movement",
    },
    {
        "id": "eval_phishing",
        "prompt": "Analyze a phishing email with attachment invoice.pdf.exe received by finance@company.com. Check email headers, attachment hash, sandbox detonation results, and similar emails to other users.",
        "expected_keywords": ["email", "attachment", "hash", "phishing", "sandbox", "header"],
        "task_type": "phishing",
    },
    {
        "id": "eval_ransomware",
        "prompt": "Investigate ransomware indicators: multiple files renamed with .encrypted extension on file server FS-01. Check for encryption processes, ransom notes, network shares affected, and backup status.",
        "expected_keywords": ["encrypt", "ransom", "backup", "file", "extension", "process"],
        "task_type": "ransomware",
    },
]


def evaluate_model(model_name: str = "fast") -> dict:
    """Run benchmark prompts and score model outputs.

    Returns evaluation results with per-prompt and aggregate scores.
    """
    results = []
    total_score = 0.0
    total_tokens = 0
    total_latency = 0.0

    for bench in BENCHMARK_PROMPTS:
        start = time.time()
        try:
            response = httpx.post(
                LITELLM_URL,
                headers={
                    "Authorization": f"Bearer {LITELLM_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": "You are a security investigation assistant. Generate Python code to investigate the security incident."},
                        {"role": "user", "content": bench["prompt"]},
                    ],
                    "max_tokens": 1024,
                    "temperature": 0.1,
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
            output = data["choices"][0]["message"]["content"]
            tokens = data.get("usage", {}).get("total_tokens", 0)
        except Exception as e:
            results.append({
                "id": bench["id"],
                "task_type": bench["task_type"],
                "score": 0.0,
                "error": str(e),
            })
            continue

        latency = time.time() - start

        # Score the output
        score = score_output(output, bench["expected_keywords"])

        results.append({
            "id": bench["id"],
            "task_type": bench["task_type"],
            "score": round(score, 3),
            "tokens": tokens,
            "latency_ms": round(latency * 1000),
            "output_length": len(output),
        })

        total_score += score
        total_tokens += tokens
        total_latency += latency

    avg_score = total_score / len(BENCHMARK_PROMPTS) if BENCHMARK_PROMPTS else 0

    return {
        "model": model_name,
        "benchmark_count": len(BENCHMARK_PROMPTS),
        "average_score": round(avg_score, 3),
        "total_tokens": total_tokens,
        "total_latency_ms": round(total_latency * 1000),
        "results": results,
    }


def score_output(output: str, expected_keywords: list) -> float:
    """Score a model output (0.0 - 1.0) based on keyword coverage and code quality."""
    if not output:
        return 0.0

    score = 0.0
    output_lower = output.lower()

    # Keyword coverage (0-0.5)
    if expected_keywords:
        matches = sum(1 for kw in expected_keywords if kw in output_lower)
        keyword_score = matches / len(expected_keywords)
        score += keyword_score * 0.5

    # Contains Python code (0-0.2)
    code_indicators = ["import ", "def ", "for ", "if ", "print(", "return ", "try:", "except"]
    code_matches = sum(1 for ci in code_indicators if ci in output)
    score += min(code_matches / 4, 1.0) * 0.2

    # Reasonable length (0-0.15)
    if 100 < len(output) < 5000:
        score += 0.15
    elif len(output) >= 5000:
        score += 0.10

    # Structure indicators (0-0.15)
    structure_indicators = ["# ", "```", "result", "finding", "conclusion"]
    struct_matches = sum(1 for si in structure_indicators if si in output_lower)
    score += min(struct_matches / 3, 1.0) * 0.15

    return min(score, 1.0)
