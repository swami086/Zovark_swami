"""Training data export — SFT JSONL and HF DPO preference JSONL from analyst feedback."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from database.pool_manager import pooled_connection


def export_training_data(min_quality_score: float = 0.7, limit: int = 1000) -> list:
    """Export high-quality investigation steps as training examples.

    Returns list of dicts with keys: instruction, response, metadata.
    """
    examples: List[dict] = []

    with pooled_connection("background") as conn:
        cur = conn.cursor()

        cur.execute(
            """
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
        """,
            (limit,),
        )

        for row in cur.fetchall():
            (
                step_id,
                prompt,
                code,
                output,
                step_type,
                tok_in,
                tok_out,
                exec_ms,
                status,
                task_type,
                verdict,
                confidence,
                risk_score,
            ) = row

            quality = compute_quality_score(
                verdict=verdict,
                confidence=confidence or 0.0,
                code=code,
                output=output,
                execution_ms=exec_ms,
            )

            if quality < min_quality_score:
                continue

            examples.append(
                {
                    "instruction": prompt,
                    "response": code,
                    "metadata": {
                        "step_id": str(step_id),
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
                }
            )

        cur.close()

    return examples


def export_dpo_preference_rows(limit: int = 5000) -> List[Dict[str, Any]]:
    """Build HF-style DPO rows from analyst_feedback vs original pipeline verdict.

    Each row: prompt, chosen, rejected (plain text summaries for preference training).
    """
    rows: List[Dict[str, Any]] = []

    with pooled_connection("background") as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                af.tenant_id,
                af.id,
                t.task_type,
                t.input,
                af.analyst_verdict,
                af.analyst_risk_score,
                af.analyst_notes,
                af.original_verdict,
                af.original_risk_score
            FROM analyst_feedback af
            JOIN agent_tasks t ON t.id = af.task_id AND t.tenant_id = af.tenant_id
            WHERE af.analyst_verdict IS NOT NULL
            ORDER BY af.created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        for (
            tenant_id,
            fid,
            task_type,
            inp,
            a_verdict,
            a_risk,
            a_notes,
            o_verdict,
            o_risk,
        ) in cur.fetchall():
            inp = inp or {}
            if isinstance(inp, str):
                try:
                    inp = json.loads(inp)
                except json.JSONDecodeError:
                    inp = {}
            prompt_parts = [
                str(inp.get("prompt") or ""),
                json.dumps(inp.get("siem_event") or {}, ensure_ascii=False)[:8000],
                f"task_type={task_type}",
            ]
            prompt = "\n\n".join(p for p in prompt_parts if p).strip()
            chosen = (
                f"verdict={a_verdict} risk={a_risk}"
                + (f" notes={a_notes}" if a_notes else "")
            )
            rejected = f"verdict={o_verdict} risk={o_risk} (original system assessment)"
            rows.append(
                {
                    "tenant_id": str(tenant_id),
                    "feedback_id": str(fid),
                    "prompt": prompt,
                    "chosen": chosen,
                    "rejected": rejected,
                }
            )
        cur.close()

    return rows


def compute_quality_score(
    verdict: str = None,
    confidence: float = 0.0,
    code: str = "",
    output: str = "",
    execution_ms: int = None,
) -> float:
    """Score a training example's quality (0.0 - 1.0)."""
    score = 0.0

    verdict_scores = {
        "true_positive": 0.3,
        "false_positive": 0.25,
        "suspicious": 0.15,
        "benign": 0.2,
    }
    score += verdict_scores.get(verdict, 0.05)

    score += min(float(confidence), 1.0) * 0.25

    code_len = len(code) if code else 0
    if 50 < code_len < 5000:
        score += 0.25
    elif 20 < code_len <= 50:
        score += 0.10
    elif code_len >= 5000:
        score += 0.15

    if output and len(output) > 10:
        score += 0.1

    if execution_ms is not None and execution_ms > 0:
        if execution_ms < 5000:
            score += 0.1
        elif execution_ms < 15000:
            score += 0.05

    return min(score, 1.0)


def write_jsonl(examples: list, output_path: str) -> str:
    """Write examples to JSONL file in chat format."""
    with open(output_path, "w", encoding="utf-8") as f:
        for ex in examples:
            record = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security investigation assistant. Generate Python code to investigate the security incident described by the user.",
                    },
                    {"role": "user", "content": ex["instruction"]},
                    {"role": "assistant", "content": ex["response"]},
                ],
                "metadata": ex["metadata"],
            }
            f.write(json.dumps(record) + "\n")
    return output_path


def write_dpo_jsonl(rows: List[Dict[str, Any]], output_path: str) -> str:
    """Write HF DPO-style JSONL: one object per line with prompt, chosen, rejected."""
    with open(output_path, "w", encoding="utf-8") as f:
        for row in rows:
            rec = {
                "prompt": row["prompt"],
                "chosen": row["chosen"],
                "rejected": row["rejected"],
                "metadata": {
                    "tenant_id": row.get("tenant_id"),
                    "feedback_id": row.get("feedback_id"),
                },
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return output_path
