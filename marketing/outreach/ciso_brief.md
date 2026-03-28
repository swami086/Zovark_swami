# ZOVARK — Autonomous SOC Investigation on Air-Gapped Infrastructure

**One-Page Technical Brief for Security Leadership**

---

## The Problem

Your SOC team processes thousands of alerts daily. 70% are false positives, but each one requires manual triage — 30-60 minutes per alert. The obvious solution — AI-assisted investigation — is blocked by data sovereignty requirements:

- **GDPR Article 44** prohibits transferring security telemetry to US cloud providers
- **HIPAA Minimum Necessary** restricts sharing PHI with third-party AI services
- **CMMC Level 2** requires controlled unclassified information to stay on-premise
- **NERC CIP-011** mandates bulk electric system data remains in your environment

Every major SOC AI tool today — CrowdStrike Charlotte AI, Microsoft Copilot for Security, Google Chronicle — requires cloud connectivity. If your data can't leave, you can't use them.

## The Solution

ZOVARK runs entirely on your infrastructure with zero data egress.

It receives SIEM alerts via webhook (Splunk HEC or Elastic format), generates Python investigation code using a local LLM, executes that code in a hardened sandbox (4-layer isolation: AST prefilter, seccomp, network deny-all, kill timer), and delivers structured verdicts with IOCs, risk scores, MITRE ATT&CK mapping, and response recommendations.

**What makes ZOVARK different:** It generates investigation code, not classifications. When ZOVARK encounters a novel attack type it has never seen before, it writes a new investigation from scratch — no template required.

## The Proof

10 out of 10 correct verdicts across three code paths:

| Attack Type | Template? | Verdict | Risk | How |
|-------------|-----------|---------|------|-----|
| SSH Brute Force (500 attempts) | Yes | true_positive | 100 | Template detection |
| SQL Injection (Juice Shop) | Yes | true_positive | 100 | Template + signal boost |
| Kerberoasting (SPN enum, RC4 downgrade) | **No** | true_positive | 75 | LLM-generated code |
| LOLBins certutil download | **No** | true_positive | 95 | LLM-generated code |
| Defense evasion (timestomping) | **No** | true_positive | 75 | LLM-generated code |
| Benign Windows Update | **No** | benign | 20 | Correctly classified |

**Juice Shop benchmark:** 99/100 on real-traffic OWASP attacks (70/70 attacks detected, 29/30 benign correct).

**Hardware:** Single NVIDIA GPU (tested on RTX 3050 4GB). Production: any NVIDIA GPU with 8GB+ VRAM.

## The Stack

Go API + Python Temporal workers + PostgreSQL 16 (pgvector) + Redis + Docker sandbox. 11 investigation templates, MITRE ATT&CK mapping for all types, IOC extraction with evidence citations linking each indicator to the source log line.

**152 commits. 65,000+ lines. 6 versioned releases. 55 database migrations.**

## The Ask

**30-day pilot.** Your SIEM, your alerts, your hardware.

We provide: deployment support, Splunk/Elastic webhook integration, weekly accuracy reviews.
You provide: SIEM webhook access, one GPU server, one analyst for ground-truth labeling.

**No data leaves your network. No cloud dependency. No per-query pricing.**

---

Contact: [your-email] | GitHub: [repo-url]
