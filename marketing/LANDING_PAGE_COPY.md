# ZOVARC — Autonomous SOC Investigation

## Headline
Your AI SOC Analyst. On-Premise. Air-Gapped.

## Subheadline
ZOVARC investigates security alerts in under 60 seconds — generating code,
executing it in a sandbox, and delivering verdicts with evidence.
No data leaves your network. Ever.

## Three Numbers
- **37 seconds** average investigation time
- **11 attack types** auto-investigated (phishing, ransomware, C2, lateral movement, etc.)
- **0 bytes** sent to cloud

## How It Works
1. SIEM alert arrives via webhook (Splunk, Elastic, Sentinel)
2. ZOVARC generates investigation code using a local LLM
3. Code executes in an isolated Docker sandbox
4. Verdict delivered with findings, IOCs, and recommendations
5. All on-premise. Air-gapped. Your data stays yours.

## Pipeline
```
SIEM Alert → Ingest → Analyze (LLM) → Execute (Sandbox) → Assess → Verdict
              1s        30s              5s                  10s      = ~45s
```

## For
- SOC teams drowning in alerts
- Organizations with data sovereignty requirements
- Defense, critical infrastructure, regulated finance
- Anyone who can't send security data to the cloud

## What You Get
- **Dashboard**: 15-page dark-mode SOC analyst interface
- **Investigation Detail**: Verdict, risk score, IOCs, findings, recommendations
- **Pipeline Timeline**: Watch each stage complete in real-time
- **SIEM Integration**: Webhook endpoints for Splunk, Elastic, Sentinel
- **Model Flexibility**: Run any GGUF model on your own GPU

## Hardware
- **Minimum**: Any NVIDIA GPU (RTX 3050+), 16GB RAM
- **Recommended**: RTX 3090 / A6000 for faster inference
- **Enterprise**: A100 for 70B+ models

## Request a Proof of Value
90-day free deployment. We measure accuracy against your team's verdicts.
No cost. No commitment. Just proof.
