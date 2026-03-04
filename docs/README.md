# Project Hydra: Enterprise AI SOC Platform

Welcome to the **Project Hydra** master documentation. Hydra is an enterprise-grade, air-gapped AI Security Operations Center (SOC) platform designed for highly regulated environments. 

## Executive Summary

Modern Security Operations Centers are overwhelmed by alert fatigue, but traditional automation (SOAR) lacks the cognitive flexibility to perform deep forensic triage. Project Hydra bridges this gap by providing an autonomous, deterministic AI analyst capable of performing Tier-1 triage and investigation **without ever relying on external APIs or risking data egress**.

Hydra's core value proposition is **Automated Tier-1 Triage without Data Egress**. By operating entirely within your sovereign boundary, Hydra reads logs, hypothesizes attack vectors, generates deterministic forensic scripts, executes them in a mathematically bounded sandbox, and presents the findings for human review.

## The 3-Pillar Moat

Hydra is secured and differentiated by its three foundational architecture pillars:

1. **Air-Gapped Sovereignty (Zero-Egress)**: Every component, from the React frontend to the inference engines and specialized routing proxies, runs locally. Complete data localization ensures absolute compliance with strict data sovereignty laws.
2. **The Hydra Intelligence Fabric**: A proprietary retrieval-augmented generation (RAG) system containing curated, SOP-driven investigation methodologies. This ensures that the AI behaves predictably, replacing generative hallucinations with deterministic, runbook-aligned execution.
3. **Episodic Security Memory**: A vector-database-backed memory system recording the success rates, risk scores, and forensic patterns of past investigations. The platform learns which methodologies work over time within your specific environment.

## Table of Contents

- [Architecture & Security Overview](./ARCHITECTURE_AND_SECURITY.md) - For CISOs and InfoSec engineering teams. Details the 8-container stack, Sandbox Physics, and AI state machine.
- [Deployment Guide](./DEPLOYMENT_GUIDE.md) - For DevOps and IT Administrators. Details sizing, Docker Compose installation, and disaster recovery.
- [SOC Analyst Playbook](./SOC_ANALYST_PLAYBOOK.md) - For Tier-1 Analysts and End Users. Operations manual for the React Dashboard and investigation approvals.
- [Developer Reference](./DEVELOPER_REFERENCE.md) - For integrators and platform engineers. Details the Go API, Temporal workflow loops, and database extensions.
