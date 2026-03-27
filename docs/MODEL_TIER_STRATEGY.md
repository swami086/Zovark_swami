# ZOVARC Model Tier Strategy

## The Three-Tier Model

ZOVARC's investigation quality depends entirely on model capability. The platform
supports three tiers, each mapped to a different use case and hardware profile.

### Tier 1: Fast (Triage)
- **Model:** Qwen2.5-1.5B or 7B (AWQ quantized)
- **VRAM:** 1.6GB - 4GB
- **Context:** 8k tokens
- **Use case:** Alert classification, entity extraction, quick risk scoring
- **Quality:** Good for sorting alerts by priority. Not sufficient for deep investigation.
- **Speed:** <2 seconds per alert
- **When to use:** Every incoming alert passes through this tier first

### Tier 2: Standard (Investigation)
- **Model:** Qwen2.5-32B (AWQ) or Llama 3 70B via cloud
- **VRAM:** 18GB local or cloud API
- **Context:** 32k-128k tokens
- **Use case:** Full investigation pipeline — code generation, log analysis, IOC correlation
- **Quality:** Production-grade. Generates reliable investigation code, extracts entities accurately.
- **Speed:** 10-30 seconds per investigation
- **When to use:** Alerts classified as medium/high risk by Tier 1

### Tier 3: Reasoning (Complex Analysis)
- **Model:** Claude, GPT-4, or local 72B
- **VRAM:** 40GB+ local or cloud API
- **Context:** 128k+ tokens
- **Use case:** Complex multi-stage attacks, APT analysis, incident report generation
- **Quality:** Highest. Handles nuanced reasoning, multi-hop attack chains, comprehensive reports.
- **Speed:** 30-120 seconds per investigation
- **When to use:** High-severity alerts, escalated investigations, report generation

## Model Routing Logic

The `model_config.py` module selects the tier based on:

1. **Alert severity** — Critical/High -> Standard or Reasoning. Low/Medium -> Fast.
2. **Investigation complexity** — Multi-entity alerts, known APT patterns -> Reasoning.
3. **Tenant configuration** — Enterprise tenants can force higher tiers.
4. **Cost budget** — Per-tenant token quotas determine max tier available.

## Deployment Configurations

| Config | Fast | Standard | Reasoning | Cloud Dependency |
|--------|------|----------|-----------|-----------------|
| `litellm_config_rtx3050.yaml` | Local 1.5B | Cloud (Groq/OR) | Cloud (Anthropic/OpenAI) | Required for investigations |
| `litellm_config.yaml` | Local 1.5B | Cloud (Groq/OR) | Cloud (Anthropic/OpenAI) | Required for investigations |
| `litellm_config_enterprise.yaml` | Local 7B | Local 32B | Local 32B | None (fully sovereign) |
| Custom A100 config | Local 7B | Local 72B | Local 72B | None (maximum quality) |

## The Honest Answer on Model Quality

A 1.5B parameter model cannot produce investigation output that a SOC analyst will trust
for anything beyond basic triage. Here is what each tier can and cannot do:

| Capability | 1.5B | 7B | 32B | 70B+ |
|-----------|------|-----|------|------|
| Alert classification (TP/FP) | Fair | Good | Excellent | Excellent |
| Entity extraction (IP/domain/hash) | Fair | Good | Excellent | Excellent |
| Python code generation for log analysis | Poor | Fair | Good | Excellent |
| MITRE ATT&CK technique mapping | Poor | Fair | Good | Excellent |
| Multi-stage attack chain reasoning | Cannot | Poor | Good | Excellent |
| Incident report generation | Poor | Fair | Good | Excellent |
| Context window (log analysis depth) | 4k tokens | 8k tokens | 32k-128k tokens | 128k+ tokens |

The 1.5B model is a valid demo/development tool. The 32B model is the minimum for
production investigations. The 70B+ model matches or exceeds Tier-1 analyst output
for standard SOC alerts.

## Human Review Threshold

Investigations with `risk_score < ZOVARC_HUMAN_REVIEW_THRESHOLD` (default: 60) or
`code_execution_failed = true` are automatically flagged for human analyst review.

The threshold is configurable per deployment via the `ZOVARC_HUMAN_REVIEW_THRESHOLD`
environment variable. The recommended value is determined from the accuracy benchmark
(`scripts/accuracy_benchmark.py`) — typically the score below which accuracy drops
below 90%.

## Recommended Production Setup

For a SOC team evaluating ZOVARC:

1. **Start with Hybrid** — Local 1.5B for triage, Groq for investigations ($0.01/inv)
2. **Validate with PoV** — Run 48-hour PoV against real alerts, measure accuracy
3. **Upgrade to Enterprise Edge** — Deploy A6000 or dual-4090 for full sovereignty
4. **Scale** — Add worker replicas via K8s HPA for throughput
