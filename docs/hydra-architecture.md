# HYDRA Architecture Reference

> AI-powered SOC automation framework — local LLMs generate and execute Python code in sandboxed environments to investigate security incidents.

**Generated:** 2026-03-06 | **Branch:** master | **Latest commit:** f0a99f7

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Database Schema](#3-database-schema)
4. [Investigation Pipeline](#4-investigation-pipeline)
5. [Security Architecture](#5-security-architecture)
6. [Entity Graph](#6-entity-graph)
7. [Bootstrap Corpus](#7-bootstrap-corpus)
8. [MSSP Features (Sprint 1L)](#8-mssp-features-sprint-1l)
9. [Sprint History](#9-sprint-history)
10. [Deployment Guide](#10-deployment-guide)
11. [Test Results](#11-test-results)
12. [Roadmap](#12-roadmap)

---

## 1. Executive Summary

HYDRA is a multi-tenant SOC automation platform that receives security alerts, generates Python investigation code via local LLMs, executes that code in hardened sandboxes, and produces structured verdicts with entity graphs. The system is designed for MSSPs (Managed Security Service Providers) serving multiple tenants from a single deployment.

### Key Metrics (Live Data)

| Metric | Value |
|--------|-------|
| Total investigations | 118 |
| Entity graph nodes | 240 |
| Entity graph edges | 216 |
| Entity observations | 497 |
| MITRE techniques loaded | 691 |
| Bootstrap corpus entries | 1,636 |
| Incident reports generated | 4 |
| Avg risk score | 82.3 |
| Avg confidence | 0.821 |
| Injection-flagged investigations | 0 |
| Worker Python codebase | 3,950 lines (23 files) |
| SQL schema | 1,116 lines (6 files) |
| Docker services | 9 active containers |

---

## 2. System Architecture

### Service Topology

```
                    ┌──────────────┐
                    │   Dashboard  │ :3000
                    │  (React/Vite)│
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
 SIEM alerts ────> │   Go API     │ :8090
                    │  (gin/RBAC)  │
                    └──┬───────┬───┘
                       │       │
              ┌────────┘       └────────┐
              │                         │
      ┌───────┴──────┐         ┌───────┴──────┐
      │  PgBouncer   │         │   Temporal   │ :7233
      │  (txn pool)  │         │   (workflows)│
      └───────┬──────┘         └───────┬──────┘
              │                         │
      ┌───────┴──────┐         ┌───────┴──────┐
      │  PostgreSQL  │ :5432   │ Python Worker │
      │  16+pgvector │         │  (Temporal)   │
      └──────────────┘         └──┬────┬───┬──┘
                                  │    │   │
                    ┌─────────────┘    │   └──────────────┐
                    │                  │                   │
            ┌───────┴──────┐   ┌──────┴───────┐   ┌──────┴───────┐
            │   LiteLLM    │   │  Embedding   │   │    Redis     │
            │  (gateway)   │   │  Server (TEI)│   │  (rate limit)│
            │  :4000       │   │  :8081       │   │  :6379       │
            └──────────────┘   └──────────────┘   └──────────────┘
```

### Docker Compose Services (9 active)

| Service | Image | Container | Port | Memory Limit | Status |
|---------|-------|-----------|------|-------------|--------|
| PostgreSQL 16 | pgvector/pgvector:pg16 | hydra-postgres | 5432 | 2G | Up (healthy) |
| Redis 7 | redis:7-alpine | hydra-redis | 6379 | 128M | Up (healthy) |
| PgBouncer | edoburu/pgbouncer | hydra-pgbouncer | — | 128M | Up (healthy) |
| Temporal 1.24.2 | temporalio/auto-setup:1.24.2 | hydra-temporal | 7233 | 512M | Up |
| LiteLLM | litellm-database:main-stable | hydra-litellm | 4000 | 1G | Up (healthy) |
| Embedding Server | text-embeddings-inference:cpu-1.2 | hydra-embedding | 8081 | 1G | Up |
| Go API | custom build | hydra-api | 8090 | 256M | Up |
| Python Worker | custom build | hydra-mvp-worker-1 | — | 512M | Up (healthy) |
| Dashboard | custom build | hydra-dashboard | 3000 | 128M | Up |

**Optional profiles:** `debug` (Temporal UI :8080), `monitoring` (Jaeger :16686), `storage` (MinIO :9000/:9001), `airgap` (Ollama :11434)

### Docker Resource Usage

| Type | Total | Active | Size |
|------|-------|--------|------|
| Images | 11 | 10 | 14.23 GB |
| Containers | 10 | 10 | 604.6 MB |
| Volumes | 5 | 2 | 119.2 MB |
| Build Cache | 26 | 0 | 4.178 GB |

### LLM Routing (LiteLLM Config)

```yaml
model_list:
  - model_name: fast                          # Primary inference
    litellm_params:
      model: openrouter/google/gemini-2.0-flash-001
      api_key: os.environ/OPENROUTER_API_KEY

  - model_name: hydra-cloud                   # Cloud fallback
    litellm_params:
      model: openrouter/google/gemini-2.0-flash-001
      api_key: os.environ/OPENROUTER_API_KEY

  - model_name: hydra-local                   # Air-gap mode (Ollama)
    litellm_params:
      model: ollama/mistral:7b-instruct-v0.3-q4_K_M
      api_base: http://ollama:11434

  - model_name: embed                         # 768-dim embeddings
    litellm_params:
      model: huggingface/BAAI/bge-base-en-v1.5
      api_base: http://embedding-server:80
      mode: embedding
```

---

## 3. Database Schema

### PostgreSQL 16.12 + Extensions

| Extension | Version | Purpose |
|-----------|---------|---------|
| pgvector | 0.8.1 | 768-dim embeddings + cosine similarity |
| pg_trgm | 1.6 | Trigram text search |
| uuid-ossp | 1.1 | UUID generation |
| plpgsql | 1.0 | Stored procedures |

### Tables (51 total, including partitions)

#### Core Tables

| Table | Live Rows | Columns | Total Size | Purpose |
|-------|-----------|---------|------------|---------|
| mitre_techniques | 691 | 11 | 7,584 kB | MITRE ATT&CK knowledge base |
| bootstrap_corpus | 1,199 | 9 | 1,176 kB | Synthetic investigation corpus |
| entities | 241 | 11 | 272 kB | Entity graph nodes |
| entity_observations | 500 | 8 | 240 kB | Entity-to-investigation links |
| entity_edges | 219 | 10 | 168 kB | Entity graph relationships |
| investigation_steps | 14 | 15 | 168 kB | Per-step investigation records |
| investigation_memory | 5 | 12 | 136 kB | Investigation episodic memory |
| agent_tasks | 8 | 22 | 112 kB | Task queue (SIEM → worker) |
| investigation_reports | 4 | 11 | 112 kB | Generated incident reports |
| approval_requests | 6 | 11 | 112 kB | Human-in-the-loop approvals |
| agent_skills | — | 24 | 96 kB | Playbook/skill definitions |
| agent_audit_log | 37 | 10 | 80 kB | Audit trail |
| usage_records | 29 | 12 | 64 kB | LLM token usage metering |
| users | 3 | 10 | 64 kB | User accounts |
| tenants | 1 | 8 | 48 kB | Tenant registry |
| agent_memory_episodic | — | 12 | 1,240 kB | Agent long-term memory |

#### Partitioned Tables

**investigations** — RANGE partitioned by `created_at` (monthly)
- 12 monthly partitions: `investigations_2026_01` through `investigations_2026_12` + `investigations_default`
- Active partition: `investigations_2026_03` (119 rows, 2,568 kB)
- 21 columns including `summary_embedding vector(768)`, `injection_detected BOOLEAN`

**audit_events** — RANGE partitioned by `created_at` (monthly)
- 12 monthly partitions + default
- Active partition: `audit_events_2026_03` (19 rows)

#### Top Indexes by Size

| Index | Table | Size |
|-------|-------|------|
| idx_mitre_embedding | mitre_techniques | 3,208 kB |
| investigations_2026_03_summary_embedding_idx | investigations_2026_03 | 1,648 kB |
| idx_memory_embedding | agent_memory_episodic | 1,208 kB |
| (12x partition embedding indexes) | investigations_* | 1,208 kB each |

### SQL Schema Files

| File | Lines | Purpose |
|------|-------|---------|
| `init.sql` | 671 | Full schema (fresh deploy) |
| `migrations/001_sprint1g_entity_graph.sql` | 166 | Entity graph tables |
| `migrations/002_schema_drift_fixes.sql` | 121 | Schema drift corrections |
| `migrations/003_sprint1e_hardening.sql` | 73 | Production hardening |
| `migrations/004_sprint1f_bootstrap.sql` | 49 | Bootstrap tables |
| `migrations/005_sprint1l_golden_path.sql` | 36 | Golden path features |
| **Total** | **1,116** | |

---

## 4. Investigation Pipeline

### Temporal Workflow: `ExecuteTaskWorkflow`

```
SIEM Alert → Go API → agent_tasks row → Temporal workflow start
    │
    ├─ 1. fetch_task                    # Load task from DB
    ├─ 2. check_rate_limit_activity     # Redis sliding window
    ├─ 3. retrieve_skill                # Match playbook/skill
    ├─ 4. fill_skill_parameters         # Inject alert data
    ├─ 5. render_skill_template         # Build investigation prompt
    │
    ├─ 6. [INJECTION SCAN]             # scan_for_injection on prompt
    ├─ 7. [PROMPT WRAPPING]            # wrap_untrusted_data with nonce delimiters
    │
    ├─ 8. generate_code                 # LLM → Python code generation
    ├─ 9. validate_code                 # AST security prefilter
    ├─10. execute_code                  # Docker sandbox execution
    │
    ├─11. check_followup_needed         # Multi-step reasoning
    │     └─ loop: generate_followup_code → validate → execute (max 2)
    │
    ├─12. check_requires_approval       # HITL gate (risk_score > threshold)
    │     └─ create_approval_request → wait for signal
    │
    ├─13. save_investigation_step       # Persist step results
    ├─14. write_investigation_memory    # Episodic memory
    │
    ├─15. extract_entities              # LLM entity extraction
    ├─16. write_entity_graph            # Upsert entities/edges/observations
    ├─17. embed_investigation           # 768-dim summary vector
    │
    ├─18. compute_blast_radius          # Recursive CTE graph traversal
    ├─19. analyze_false_positive        # Confidence scoring + LLM reasoning
    ├─20. generate_incident_report      # LLM report + PDF generation
    │
    ├─21. log_audit_event               # Audit trail
    ├─22. record_usage                  # Token metering
    ├─23. update_task_status            # Mark complete
    └─24. decrement_active_activity     # Rate limit cleanup
```

### Registered Activities (34 total)

**Core pipeline (worker/activities.py — 862 lines):**
fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, log_audit_event, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template, check_rate_limit_activity, decrement_active_activity

**Entity graph (worker/entity_graph.py — 418 lines):**
extract_entities, write_entity_graph, embed_investigation

**Bootstrap (worker/bootstrap/ — 587 lines):**
load_mitre_techniques, load_cisa_kev, generate_synthetic_investigation, process_bootstrap_entity, list_techniques

**Intelligence (worker/intelligence/ — 312 lines):**
compute_blast_radius, analyze_false_positive

**Skills (worker/skills/ — 155 lines):**
run_deobfuscation

**Reporting (worker/reporting/ — 252 lines):**
generate_incident_report

### Worker File Breakdown

| File | Lines | Purpose |
|------|-------|---------|
| worker/workflows.py | 961 | Temporal workflow orchestration |
| worker/activities.py | 862 | Core 20 activities |
| worker/entity_graph.py | 418 | Entity extraction + graph write + embedding |
| worker/bootstrap/activities.py | 375 | Bootstrap pipeline activities |
| worker/reporting/incident_report.py | 252 | LLM incident report + PDF |
| worker/intelligence/fp_analyzer.py | 203 | False positive confidence |
| worker/skills/deobfuscation.py | 155 | Sandbox deobfuscation |
| worker/bootstrap/workflow.py | 133 | Bootstrap Temporal workflow |
| worker/entity_normalize.py | 122 | Entity normalization + hashing |
| worker/intelligence/blast_radius.py | 109 | Recursive CTE graph traversal |
| worker/security/injection_detector.py | 92 | Prompt injection detection |
| worker/prompts/entity_extraction.py | 59 | LLM extraction prompt template |
| worker/main.py | 54 | Worker entrypoint |
| worker/bootstrap/mitre_parser.py | 52 | MITRE ATT&CK STIX parser |
| worker/redis_client.py | 44 | Redis rate limiting client |
| worker/security/prompt_sanitizer.py | 31 | Nonce-delimited prompt wrapping |
| worker/bootstrap/cisa_parser.py | 27 | CISA KEV parser |
| **Total** | **3,950** | |

---

## 5. Security Architecture

### Sandbox Layers (Defense-in-Depth)

```
Layer 1: AST Prefilter (sandbox/ast_prefilter.py — 90 lines)
    │   Blocks: eval, exec, subprocess, socket, ctypes, importlib, __import__
    │   Static analysis before execution
    │
Layer 2: Seccomp Profile (sandbox/seccomp_profile.json — 861 lines)
    │   Syscall allowlist/blocklist
    │   Kernel-level enforcement
    │
Layer 3: Docker Isolation
    │   --network=none (no network access)
    │   --read-only filesystem
    │   --memory=256m --cpus=0.5
    │   --pids-limit=50
    │
Layer 4: Kill Timer (sandbox/kill_timer.py — 64 lines)
        30-second hard timeout
        Process termination
```

### Prompt Injection Defense (Sprint 1L)

**Detection** (`worker/security/injection_detector.py`):
- 4 regex pattern categories: role_override, token_injection, verdict_manipulation, prompt_extraction
- Scoring: 2+ categories → `injection_detected`, 1 → `suspicious`, 0 → `clean`
- Sub-millisecond execution, runs before LLM call

**Sanitization** (`worker/security/prompt_sanitizer.py`):
- Generates random UUID hex nonce per request
- Wraps untrusted data in XML-style delimiters: `<DATA-{nonce}:investigation>...</DATA-{nonce}:investigation>`
- System instruction tells LLM to treat delimited content as passive data only

**Pipeline integration:**
- Injection scan runs on raw prompt + log data before code generation
- Flagged investigations: `UPDATE investigations SET injection_detected = true`
- Similarity search excludes injection-flagged investigations: `AND NOT COALESCE(injection_detected, false)`

### Authentication

| Layer | Method |
|-------|--------|
| Go API | JWT tokens (HS256), RBAC (admin/analyst/viewer) |
| PostgreSQL | SCRAM-SHA-256 |
| PgBouncer | SCRAM-SHA-256 pass-through |
| LiteLLM | Bearer token (`sk-hydra-dev-2026`) |
| MinIO | Access key + secret key |

---

## 6. Entity Graph

### Entity Types (8)

| Type | Count | % |
|------|-------|---|
| domain | 60 | 25.0% |
| file_hash | 52 | 21.7% |
| process | 43 | 17.9% |
| ip | 27 | 11.3% |
| device | 24 | 10.0% |
| user | 18 | 7.5% |
| url | 13 | 5.4% |
| email | 3 | 1.3% |
| **Total** | **240** | |

### Edge Types (9 active of 11 defined)

| Type | Count | % |
|------|-------|---|
| communicates_with | 80 | 37.0% |
| executed | 31 | 14.4% |
| logged_into | 22 | 10.2% |
| resolved_to | 18 | 8.3% |
| associated_with | 17 | 7.9% |
| downloaded | 15 | 6.9% |
| parent_of | 12 | 5.6% |
| contains | 12 | 5.6% |
| accessed | 9 | 4.2% |
| **Total** | **216** | |

### Observation Roles (8)

| Role | Count | % |
|------|-------|---|
| attacker | 120 | 24.1% |
| indicator | 111 | 22.3% |
| artifact | 94 | 18.9% |
| victim | 55 | 11.1% |
| infrastructure | 51 | 10.3% |
| destination | 39 | 7.8% |
| target | 15 | 3.0% |
| source | 12 | 2.4% |
| **Total** | **497** | |

### Entity Normalization

Handled by `worker/entity_normalize.py` (122 lines):

| Function | Logic |
|----------|-------|
| `normalize_ip()` | IPv4 as-is, IPv6 expanded, strip ports/brackets, defang `[.]` |
| `normalize_domain()` | Lowercase, strip `www.`, trailing dot, handle `hxxp`/defang |
| `normalize_file_hash()` | Lowercase, validate hex + length (32/40/64) |
| `normalize_url()` | Lowercase scheme+host, strip tracking params, defang |
| `normalize_email()` | Lowercase, strip plus-addressing |
| `compute_entity_hash()` | SHA256 of `"{type}:{normalized}"` for cross-tenant dedup |

### Similarity Search

- pgvector cosine similarity (`<=>` operator) on `summary_embedding vector(768)`
- IVFFlat indexes (lists=100) on investigation embeddings
- Filters: same tenant, excludes injection-flagged investigations
- Used by: FP analyzer (find similar past investigations)

---

## 7. Bootstrap Corpus

### Pipeline: `BootstrapCorpusWorkflow`

```
MITRE ATT&CK STIX data
    │
    ├─ load_mitre_techniques      → 691 techniques parsed + embedded (768-dim)
    ├─ load_cisa_kev              → 1,536 KEV entries loaded
    │
    └─ For each technique (batched):
        ├─ generate_synthetic_investigation   → LLM generates realistic alert
        ├─ process_bootstrap_entity           → Extract + write entity graph
        └─ embed_investigation                → Store summary vector
```

### Sprint 1H Results (100 techniques at scale)

| Metric | Value |
|--------|-------|
| Techniques processed | 100/100 (0 failures) |
| Investigations created | 118 total (113 bootstrap + 5 production) |
| Entities created | 240 (deduped via entity_hash) |
| Edges created | 216 |
| Observations | 497 |
| Avg observation per entity | 2.1 |

### Investigation Verdicts

| Verdict | Count | % |
|---------|-------|---|
| true_positive | 105 | 89.0% |
| suspicious | 13 | 11.0% |
| **Total** | **118** | |

### Investigation Sources

| Source | Count |
|--------|-------|
| bootstrap | 113 |
| production | 5 |

---

## 8. MSSP Features (Sprint 1L)

### 8.1 Blast Radius Analysis

**Activity:** `compute_blast_radius` (109 lines)

- Recursive CTE traverses entity_edges via BFS
- Default: 2-hop max, 72-hour time window
- Returns: affected entities with hop distance, related investigations sharing entities
- Output: `{affected_entities, affected_investigations, total_entities, max_threat_score, summary}`

### 8.2 False Positive Confidence

**Activity:** `analyze_false_positive` (203 lines)

5-step pipeline:
1. Embed current summary → pgvector similarity search
2. Entity overlap query (investigations sharing 2+ entities)
3. Compute base confidence (0.40–0.95 range)
4. LLM reasoning chain with sanitized prompts
5. Update investigation confidence + analyst_feedback JSONB

### 8.3 Deobfuscation

**Activity:** `run_deobfuscation` (155 lines)

- Generates Python deobfuscation script dynamically
- Executes in hardened Docker sandbox (same as investigation sandbox)
- Supports: base64, hex, PowerShell-encoded, URL encoding
- Returns decoded payloads per method

### 8.4 Incident Reports

**Activity:** `generate_incident_report` (252 lines)

- Single LLM call for 3 sections: executive summary, technical timeline, remediation steps
- PDF generation via reportlab (SimpleDocTemplate, Paragraph, Spacer)
- Stored in `investigation_reports` table (both markdown + PDF BYTEA)
- 4 reports generated to date

---

## 9. Sprint History

```
f0a99f7 Sprint 1H: Bootstrap entity graph at scale — 100 synthetic investigations, 240 entities, 216 edges
5a9ac30 Sprint 1L: Golden Path — blast radius, deobfuscation, incident reports, FP confidence + injection defense
59753e0 Sprint 1F: Bootstrap corpus — MITRE ATT&CK (691 techniques) + CISA KEV (1536 vulns) loader, synthetic investigation generator, entity seeding pipeline
e433104 Sprint 1E: Production hardening — sandbox limits, sync commit, SCRAM-SHA-256, audit events, schema drift fixes, PgBouncer routing fix
e60bbd3 Sprint 1G: Entity graph schema — investigations, entities, edges, observations + normalization + extraction pipeline
f52f070 Block 1.5: K8s deployment verification — skipped (no cluster), manifests validated via kustomize build
0fd15af Block 1.4b: Kubernetes manifests — Kustomize + HPA (2-50 workers) + NetworkPolicy + 3 overlays (dev/prod/airgap)
986809f Block 1.4a: Load testing — baseline 17inv/min, scaled 21inv/min, stress 100 tasks
fb76387 Block 1.3: PgBouncer + Postgres tuning (max_conn=200, wal_level=replica, sync_commit=off) + Redis rate limiting + table partitioning
329aac3 Block 1.2: Multi-worker scaling — docker compose --scale worker=N
74931d6 Block 1.1: Stateless worker + worker identity tracking
9d7c691 Sprint 12: 20/20 harness + 5/5 integration - test framework complete
```

---

## 10. Deployment Guide

### Prerequisites

- Docker Desktop with Docker Compose V2
- NVIDIA GPU with CUDA (for local vLLM inference) OR OpenRouter API key (for cloud LLM)
- 16 GB RAM minimum, 32 GB recommended

### Quick Start

```bash
# Clone
git clone https://github.com/7inaydas-cmyk/hydra-mvp.git
cd hydra-mvp

# Configure environment
cp .env.example .env
# Edit .env: set OPENROUTER_API_KEY, POSTGRES_PASSWORD, etc.

# Start all services
docker compose up -d

# Verify health
docker compose ps

# Seed demo data (skills, users, tenants)
docker exec hydra-mvp-worker-1 python scripts/seed_demo.py
```

### PgBouncer Configuration

| Parameter | Value |
|-----------|-------|
| Pool mode | transaction |
| Auth type | scram-sha-256 |
| Max client connections | 400 |
| Default pool size | 25 |
| Min pool size | 5 |
| Reserve pool size | 20 |
| Max DB connections | 50 |
| Query timeout | 30s |

### PostgreSQL Tuning

Custom `config/postgresql.conf`:
- `max_connections = 200`
- `wal_level = replica`
- `synchronous_commit = off` (worker default, `on` for critical writes)
- pgvector IVFFlat indexes with `lists = 100`

### Kubernetes Deployment

K8s manifests in `k8s/` with Kustomize:

```
k8s/
├── base/
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── secrets.yaml.example
│   ├── api/
│   ├── dashboard/
│   ├── litellm/
│   ├── pgbouncer/
│   ├── postgres/
│   ├── redis/
│   ├── temporal/
│   └── worker/
└── overlays/
    ├── dev/
    ├── production/
    └── airgap/
```

- HPA: 2–50 worker replicas based on CPU/memory
- NetworkPolicy: worker → pgbouncer, temporal, litellm, redis only
- 3 overlays: dev (defaults), production (scaled resources), airgap (Ollama + no external network)

---

## 11. Test Results

### Test Corpus

5 threat categories × 4 difficulty levels = 20 test cases:

| Category | Files |
|----------|-------|
| brute_force | 4 JSON scenarios |
| c2 | 4 JSON scenarios |
| lateral_movement | 4 JSON scenarios |
| phishing | 4 JSON scenarios |
| ransomware | 4 JSON scenarios |

### Test Harness Results (Sprint 12)

- `scripts/test_harness.py`: **20/20 passed**
- `scripts/test_integration.py`: **5/5 passed**

### Load Test Results (Block 1.4a)

| Test | Result |
|------|--------|
| Baseline (1 worker) | 17 investigations/min |
| Scaled (multi-worker) | 21 investigations/min |
| Stress (100 tasks) | All completed, no crashes |

### Task Status Distribution

| Status | Count |
|--------|-------|
| completed | 5 |
| failed | 2 |
| pending | 1 |
| **Total** | **8** |

### Audit Events

19 audit events recorded in `audit_events_2026_03`.

---

## 12. Roadmap

### Completed

- [x] Sprint 12: Test framework (20/20 + 5/5)
- [x] Block 1.1: Stateless worker + identity tracking
- [x] Block 1.2: Multi-worker scaling
- [x] Block 1.3: PgBouncer + Postgres tuning + Redis rate limiting
- [x] Block 1.4a: Load testing
- [x] Block 1.4b: Kubernetes manifests
- [x] Block 1.5: K8s validation
- [x] Sprint 1G: Entity graph schema + extraction pipeline
- [x] Sprint 1E: Production hardening
- [x] Sprint 1F: Bootstrap corpus (MITRE + CISA KEV)
- [x] Sprint 1L: Golden Path (injection defense, blast radius, deobfuscation, reports, FP confidence)
- [x] Sprint 1H: Bootstrap at scale (100 techniques)

### Remaining

- [ ] Sprint 1I: Model Tiering + Prompt Versioning
- [ ] Sprint 1J: Autoscaling + Circuit Breakers
- [ ] Sprint 1K: Cross-Tenant Intelligence
- [ ] Sprint 2A: Detection Engine
- [ ] Sprint 2B: SOAR Integration
