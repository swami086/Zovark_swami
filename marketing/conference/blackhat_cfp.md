# BlackHat USA 2026 Arsenal — Call for Papers

## Title

HYDRA: Autonomous Air-Gapped SOC Investigation with Local LLM Code Generation

## Abstract

We present HYDRA, an autonomous security investigation platform that generates, executes, and assesses investigation code using a locally-hosted large language model — entirely air-gapped with zero data egress. Unlike cloud-dependent AI SOC tools (CrowdStrike Charlotte AI, Microsoft Copilot for Security), HYDRA runs on a single NVIDIA GPU behind your firewall, making it deployable in environments subject to GDPR, HIPAA, NERC CIP, and CMMC data sovereignty requirements.

### The Architecture

HYDRA implements a five-stage investigation pipeline orchestrated by Temporal durable workflows: (1) alert ingestion with Redis-backed deduplication and PII masking, (2) investigation code generation via local LLM (Qwen2.5-14B, quantized to 4-bit), (3) sandboxed execution in a Docker container with AST prefiltering, seccomp profile, cap-drop ALL, network deny-all, and a 120-second kill timer, (4) LLM-powered verdict assessment with schema validation, and (5) structured persistence with MITRE ATT&CK mapping and entity graph correlation.

### What Makes This Novel: Code Generation, Not Classification

Most AI security tools classify alerts into categories. HYDRA generates Python investigation code tailored to each specific alert. This distinction matters most for novel attacks: when HYDRA encounters an attack type it has never seen — Kerberoasting via SPN enumeration, LOLBins certutil abuse, defense evasion via timestomping — it writes a new investigation script from scratch. No template. No prior training on that attack type. The LLM receives the SIEM alert data, generates Python that analyzes the specific indicators present, and the sandbox executes it safely.

We demonstrate three distinct code paths: (A) template-based investigation using domain-specific skill templates for known attack types, (B) template with LLM parameter filling for semi-known attacks, and (C) full LLM code generation for completely novel attack types. All three paths produce structured verdicts with IOC extraction, evidence citations linking each indicator to the source log line, and confidence scoring.

### Benchmark Results

We evaluated HYDRA against the OWASP Juice Shop benchmark corpus of 100 real-traffic alerts (70 attacks across 8 categories + 30 benign). Results: 99% overall accuracy (70/70 attack detection, 29/30 benign classification). Average investigation time: 15 seconds for template path, 120 seconds for full LLM generation on a single RTX 3050 (4GB VRAM).

On novel attack types with no matching template (Path C), HYDRA achieved 10/10 correct verdicts including Kerberoasting (T1558.003), LOLBins certutil download (T1105), and defense evasion timestomping (T1070.006). Each investigation produced actionable IOCs with evidence citations and MITRE ATT&CK technique mapping.

### The Sandbox Threat Model

Generated code is untrusted by design. HYDRA's four-layer sandbox provides defense in depth: (1) AST prefilter blocks dangerous imports (os, sys, subprocess, socket, eval, exec) and injection patterns before execution, (2) seccomp profile restricts system calls at the kernel level, (3) Docker container runs with network=none, read-only filesystem, 512MB memory limit, and all capabilities dropped, (4) kill timer terminates execution after 120 seconds. A safety wrapper guarantees valid JSON output even if the generated code crashes.

### Live Demo

We will demonstrate HYDRA processing a live attack scenario: a Splunk webhook delivers a brute force alert, HYDRA generates investigation code, executes it in the sandbox, and delivers a structured verdict with IOCs — all in under 60 seconds, on a laptop, with no internet connection.

### Availability

HYDRA is an open-architecture platform: 152 commits, 65,000+ lines of production code (Go + Python + TypeScript), with Kubernetes manifests, Helm charts, and Terraform modules for production deployment. The codebase includes Prometheus/Grafana observability, SOAR response playbooks with approval gates, and a self-generating Sigma detection engine.

## Speaker Information

[Your name and bio]

## Tool Category

Arsenal / AI & Machine Learning / Blue Team

## Requirements

One laptop with NVIDIA GPU (provided by presenter). No internet required for demo.
