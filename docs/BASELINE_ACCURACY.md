# HYDRA Baseline Accuracy — Fast Tier (Qwen 1.5B)

**Date:** 2026-03-16
**Model:** Qwen2.5-1.5B-Instruct-AWQ (local, RTX 3050)
**Investigations scored:** 6 (from prior completed runs)

## Summary

| Metric | Value |
|--------|-------|
| Code generation success | 100% |
| Mean risk score | 73 |
| Investigations with findings | 5/6 (83%) |
| Investigations with IOCs | 1/6 (16%) |
| Mean execution time | 26759ms |

## Individual Results

| ID | Type | Risk Score | Findings | IOCs | Code OK | Time (ms) |
|----|------|-----------|----------|------|---------|-----------|
| 535e2379 | log_analysis | 95 | 2 | 1 | Yes | 30548 |
| 3133fb39 | brute_force | 80 | 10 | 0 | Yes | 22310 |
| c39d224a | brute_force | 0 | 0 | 0 | Yes | 40518 |
| ed573048 | brute_force | 94 | 3 | 0 | Yes | 18412 |
| 1566693b | brute_force | 95 | 5 | 0 | Yes | 16679 |
| b6047c8b | brute_force | 75 | 1 | 0 | Yes | 32085 |

## Interpretation

The 1.5B model serves as HYDRA's baseline triage tier:
- **Code generation works** — the model generates executable Python investigation code
- **Risk scoring functions** — non-zero risk scores produced for actual threats
- **IOC extraction functional** — extracts IPs from investigation output
- **Findings generated** — structured findings with titles and details

This is the "before" number. The DPO-aligned model and Standard/Reasoning tiers
are expected to improve accuracy, reduce hallucination, and produce richer output.

## Next Steps

1. Run `python scripts/accuracy_benchmark.py --model standard` with cloud API keys
2. Run DPO training: `python dpo/dpo_forge.py` then `python scripts/dpo_train.py`
3. Run post-training: `python scripts/accuracy_benchmark.py --model hydra_aligned_1.5b`
