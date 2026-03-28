"""Training data export — converts investigations into fine-tuning JSONL format.

Exports investigation steps as instruction/response pairs suitable for
supervised fine-tuning of code generation models.
"""

import json
import os
import psycopg2

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")


def _get_db():
    return psycopg2.connect(DATABASE_URL)


def export_training_data(min_quality_score: float = 0.7, limit: int = 1000) -> list:
    """Export high-quality investigation steps as training examples.

    Returns list of dicts with keys: instruction, response, metadata.
    """
    conn = _get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            s.id,
            s.summary_prompt,
            s.generated_code,
            s.output,
            s.step_type,
            s.tokens_used_input,
            s.tokens_used_output,
            s.execution_ms,
            s.status,
            t.task_type,
            i.verdict,
            i.confidence,
            i.risk_score
        FROM investigation_steps s
        JOIN agent_tasks t ON s.task_id = t.id
        LEFT JOIN investigations i ON i.task_id = t.id
        WHERE s.status = 'completed'
          AND s.generated_code IS NOT NULL
          AND s.generated_code != ''
          AND s.output IS NOT NULL
        ORDER BY s.created_at DESC
        LIMIT %s
    """, (limit,))

    examples = []
    for row in cur.fetchall():
        step_id, prompt, code, output, step_type, tok_in, tok_out, exec_ms, status, task_type, verdict, confidence, risk_score = row

        quality = compute_quality_score(
            verdict=verdict,
            confidence=confidence or 0.0,
            code=code,
            output=output,
            execution_ms=exec_ms,
        )

        if quality < min_quality_score:
            continue

        examples.append({
            "instruction": prompt,
            "response": code,
            "metadata": {
                "step_id": step_id,
                "step_type": step_type,
                "task_type": task_type,
                "verdict": verdict,
                "confidence": float(confidence) if confidence else None,
                "risk_score": int(risk_score) if risk_score else None,
                "quality_score": round(quality, 3),
                "tokens_input": tok_in,
                "tokens_output": tok_out,
                "execution_ms": exec_ms,
            },
        })

    cur.close()
    conn.close()
    return examples


def compute_quality_score(verdict: str = None, confidence: float = 0.0, code: str = "", output: str = "", execution_ms: int = None) -> float:
    """Score a training example's quality (0.0 - 1.0).

    Factors:
    - Verdict clarity (true_positive/false_positive > suspicious > None)
    - Confidence level
    - Code length (too short or too long penalized)
    - Output presence and length
    - Execution speed (faster = better)
    """
    score = 0.0

    # Verdict clarity (0-0.3)
    verdict_scores = {
        "true_positive": 0.3,
        "false_positive": 0.25,
        "suspicious": 0.15,
        "benign": 0.2,
    }
    score += verdict_scores.get(verdict, 0.05)

    # Confidence (0-0.25)
    score += min(float(confidence), 1.0) * 0.25

    # Code quality heuristic (0-0.25)
    code_len = len(code) if code else 0
    if 50 < code_len < 5000:
        score += 0.25
    elif 20 < code_len <= 50:
        score += 0.10
    elif code_len >= 5000:
        score += 0.15

    # Output presence (0-0.1)
    if output and len(output) > 10:
        score += 0.1

    # Execution speed (0-0.1)
    if execution_ms is not None and execution_ms > 0:
        if execution_ms < 5000:
            score += 0.1
        elif execution_ms < 15000:
            score += 0.05

    return min(score, 1.0)


def write_jsonl(examples: list, output_path: str) -> str:
    """Write examples to JSONL file in chat format."""
    with open(output_path, "w") as f:
        for ex in examples:
            # OpenAI chat fine-tuning format
            record = {
                "messages": [
                    {"role": "system", "content": "You are a security investigation assistant. Generate Python code to investigate the security incident described by the user."},
                    {"role": "user", "content": ex["instruction"]},
                    {"role": "assistant", "content": ex["response"]},
                ],
                "metadata": ex["metadata"],
            }
            f.write(json.dumps(record) + "\n")
    return output_path
