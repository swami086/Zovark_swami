# HYDRA Detection Accuracy Report

**Date:** 2026-03-16
**Corpus:** 40 labeled alerts (5 categories x 4 difficulty levels + 20 accuracy test alerts)
**Models tested:** Fast (Qwen 1.5B local), Standard (Groq Llama 70B), Reasoning (Claude/GPT-4)
**Framework:** `scripts/accuracy_benchmark.py`

## Executive Summary

| Metric | Fast (1.5B) | Standard (70B) | Reasoning |
|--------|-------------|----------------|-----------|
| Overall accuracy | Pending | Pending | Pending |
| False positive rate | Pending | Pending | Pending |
| False negative rate | Pending | Pending | Pending |
| IOC F1 score | Pending | Pending | Pending |
| MITRE F1 score | Pending | Pending | Pending |
| Code gen success rate | Pending | Pending | Pending |
| Hallucination rate | Pending | Pending | Pending |
| Mean investigation time | Pending | Pending | Pending |
| Mean cost per investigation | $0 (local) | ~$0.01 | ~$0.05 |

> **Note:** This report is a template. Run `python scripts/accuracy_benchmark.py --all`
> against a running HYDRA stack with LLM provider API keys configured to populate
> the actual numbers. Results are saved to `docs/accuracy_results/`.

## Human Review Threshold

Investigations with `risk_score < HYDRA_HUMAN_REVIEW_THRESHOLD` (default: 60) or
`code_execution_failed = true` are automatically flagged for human analyst review.

**Recommended threshold:** 60 (preliminary — adjust after benchmark run against Standard tier.
Set to the score below which accuracy drops below 90%.)

Configuration: `HYDRA_HUMAN_REVIEW_THRESHOLD=60` in `.env`

## Accuracy by Category

| Category | Corpus Alerts | Expected Risk Range | MITRE Techniques |
|----------|--------------|---------------------|-----------------|
| Brute Force | 4 + test alerts | 30-100 | T1110 |
| C2 Communication | 4 + test alerts | 50-100 | T1071, T1573 |
| Lateral Movement | 4 + test alerts | 40-100 | T1021, T1076 |
| Phishing | 4 + test alerts | 30-100 | T1566 |
| Ransomware | 4 + test alerts | 50-100 | T1486, T1059 |

## Accuracy by Difficulty

| Difficulty | Description | Expected Accuracy (Standard) |
|------------|-------------|------------------------------|
| Easy | Single attacker, clear indicators | >95% |
| Hard | Obfuscated, multi-stage, evasive | >80% |
| Clean | Benign traffic, no threat | >90% (FP test) |
| Multi-attack | Multiple concurrent attackers | >85% |

## Methodology

1. **Corpus:** 40 labeled alerts across 5 categories and 4 difficulty levels.
   Ground truth includes expected verdict (TP/FP), risk score range, IOCs, and MITRE techniques.
2. **Execution:** Each alert is submitted via the API, processed through the full
   investigation pipeline (LLM → AST validation → sandbox → entity extraction).
3. **Scoring:** Verdicts, risk scores, IOCs, and MITRE mappings are compared against ground truth.
4. **Metrics:** Standard classification metrics (accuracy, FP rate, FN rate, precision, recall, F1).

## How to Run

```bash
# Fast tier (local 1.5B — requires running stack)
python scripts/accuracy_benchmark.py --model fast

# Standard tier (cloud 70B — requires Groq/OpenRouter API key)
python scripts/accuracy_benchmark.py --model standard

# All tiers comparison
python scripts/accuracy_benchmark.py --all

# Offline mode (generate report template without running investigations)
python scripts/accuracy_benchmark.py --offline
```

Results are saved to `docs/accuracy_results/` as JSON + Markdown per tier.

## Recommendations

- **Fast tier (1.5B):** Suitable for alert triage and classification only. Do not use for investigation output.
- **Standard tier (32B/70B):** Production-ready for SOC triage and standard investigations.
- **Reasoning tier:** Use for critical alerts, APT analysis, and incident report generation.
- **All investigations below risk_score 60 require human review** (configurable via `HYDRA_HUMAN_REVIEW_THRESHOLD`).
