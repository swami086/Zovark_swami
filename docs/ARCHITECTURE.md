# HYDRA Platform Architecture

**Version:** v0.10.1
**Commit:** f1974bd
**Date:** 2026-03-13
**Status:** In Development

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Component Inventory](#component-inventory)
4. [Go API Gateway](#go-api-gateway)
5. [Python Worker](#python-worker)
6. [Database Layer](#database-layer)
7. [Dashboard](#dashboard)
8. [MCP Server](#mcp-server)
9. [Infrastructure Services](#infrastructure-services)
10. [Network Topology](#network-topology)
11. [Security Architecture](#security-architecture)
12. [Authentication & Authorization](#authentication--authorization)
13. [Sandbox Execution](#sandbox-execution)
14. [LLM Routing](#llm-routing)
15. [Data Flow](#data-flow)
16. [Configuration & Environment](#configuration--environment)
17. [Dependencies](#dependencies)
18. [Testing](#testing)
19. [Deployment](#deployment)
20. [Known Gaps](#known-gaps)

---

## Overview

HYDRA is an AI-powered SOC (Security Operations Center) automation platform. It receives security alerts, uses local LLMs to generate investigation code, executes that code in sandboxed containers, and returns structured findings. The platform is designed for on-premises deployment with no mandatory cloud dependencies.

**Core value proposition:** Automate Tier-1 SOC analyst work -- triage alerts, investigate indicators, correlate entities, and generate incident reports -- using locally-hosted LLMs for privacy and cost control.

### Key Design Principles

- **Local-first inference:** All LLM processing runs on local GPU hardware (RTX 3050 / 4GB VRAM target). Cloud providers are optional fallbacks only.
- **Defense in depth:** Four-layer sandbox (AST prefilter, seccomp, network isolation, kill timer) protects against malicious code generation.
- **Multi-tenant isolation:** Tenant-scoped data, per-tenant rate limits, RBAC, and audit logging.
- **Durable execution:** Temporal workflows survive restarts, retries, and partial failures.
- **Air-gap capable:** Ollama fallback mode for fully disconnected environments.

---

## System Architecture

```
                         +------------------+
                         |    Dashboard     |
                         |  React 19 :3000  |
                         +--------+---------+
                                  |
                                  | HTTPS / REST
                                  v
                         +------------------+
                         |   Go API Gateway |
                         |   Gin :8090      |
                         +--+----+----+---+-+
                            |    |    |   |
              +-------------+    |    |   +-------------+
              |                  |    |                  |
              v                  v    v                  v
     +--------+------+  +-------+--+ +--+-------+  +----+------+
     |  PostgreSQL   |  | Temporal | | Redis    |  |   NATS    |
     |  16+pgvector  |  | 1.24.2   | | 7-alpine |  | (events)  |
     |  :5432        |  | :7233    | | :6379    |  |           |
     +--------+------+  +----+-----+ +----------+  +-----------+
              |               |
              |               v
              |      +--------+--------+
              |      |  Python Worker  |
              |      |  Temporal SDK   |
              |      +---+----+----+---+
              |          |    |    |
              |    +-----+    |    +-----+
              |    |          |          |
              v    v          v          v
         +----+---+--+ +-----+----+ +---+--------+
         | LiteLLM   | |  MinIO   | |  Sandbox   |
         | :4000     | |  :9000   | |  Container |
         +-----+-----+ +----------+ +---+--------+
               |                         |
        +------+------+                  |
        |             |            AST + seccomp
        v             v            + network=none
   +----+----+  +-----+-----+     + kill timer
   | vLLM    |  | vLLM      |
   | Chat    |  | Embed     |
   | :8000   |  | :8001     |
   +---------+  +-----------+
```

**Host-exposed ports (v0.10.1):** Only the Dashboard (3000) and API Gateway (8090) are exposed to the host network. All other services communicate exclusively over the `hydra-internal` Docker bridge network.

---

## Component Inventory

| Component | Language | Key Files | Scale |
|-----------|----------|-----------|-------|
| Go API Gateway | Go 1.22+ | 27 .go files | ~58 endpoints |
| Python Worker | Python 3.11+ | 39+ .py files | 10 workflows, 95 activities |
| Database | PostgreSQL 16 | 32 migrations | ~43 tables |
| Dashboard | TypeScript 5.9 | React 19 + Vite 7 | SPA |
| MCP Server | TypeScript | Node.js | 7 tools, 7 resources, 6 prompts |
| Docker Stack | YAML | docker-compose.yml | ~20 services |

---

## Go API Gateway

**Location:** `api/`

The API gateway is a Go service built with Gin 1.9.1. It handles all external HTTP traffic, enforces authentication and authorization, and dispatches work to Temporal.

### Endpoint Groups (~58 endpoints across 27 files)

| Group | Responsibilities | Key Patterns |
|-------|-----------------|--------------|
| **Auth** | Login, logout, token refresh, TOTP 2FA enrollment/verify | JWT access (15min) + refresh (7d httpOnly cookie) |
| **RBAC** | Role-based access control, permission checks | admin, analyst, viewer roles |
| **SIEM** | Alert ingestion from external SIEM platforms | Webhook receivers, alert normalization |
| **Playbooks** | SOAR playbook management and triggering | CRUD + execution via Temporal |
| **Tenants** | Tenant CRUD, per-tenant configuration | Multi-tenant isolation |
| **Shadow Mode** | Run new models alongside production without affecting output | A/B comparison |
| **Kill Switch** | Emergency disable of LLM-generated code execution | Global and per-tenant |
| **Token Quotas** | Per-tenant LLM token usage limits | Redis-backed counters |
| **NATS** | Event publishing for real-time notifications | Pub/sub integration |
| **OIDC** | External identity provider integration | JWKS verification, issuer/audience validation |
| **TOTP** | Time-based one-time password 2FA | Enrollment + verification |
| **Webhooks** | Outbound webhook delivery on events | Configurable per tenant |
| **Models** | Model registry management | CRUD for model configurations |
| **A/B Tests** | Model A/B test configuration | Traffic splitting |
| **Retention** | Data retention policy management | Per-tenant TTLs |
| **Integrations** | External system connections | SIEM, ticketing |
| **Feedback** | Investigation quality feedback collection | Analyst ratings |
| **Costs** | Investigation cost tracking and reporting | Per-model cost roll-ups |
| **Entities** | Entity graph queries (IPs, domains, users, hashes) | Cross-investigation correlation |
| **Notifications** | Alert and status notifications | NATS-backed delivery |

### Middleware Stack (applied in order)

1. **CORS** -- Strict origin (`localhost:3000`), credentials allowed
2. **Request ID** -- UUID per request for tracing
3. **Structured Logging** -- JSON logs with request context
4. **Auth Rate Limiting** -- 10 attempts per 15 minutes per IP
5. **JWT Validation** -- Access token from httpOnly cookie, signing method enforcement
6. **RBAC Check** -- Role-based endpoint access
7. **Tenant Scoping** -- Tenant ID from JWT claims, enforced on all queries
8. **Audit Logging** -- All mutating operations logged to `audit_events` table

---

## Python Worker

**Location:** `worker/`

The worker is a Python service that connects to Temporal and executes investigation workflows. It hosts all LLM interaction, code generation, sandbox execution, and result processing.

### Workflows (10)

Workflows are durable, resumable execution graphs managed by Temporal. Each workflow orchestrates a sequence of activities.

| Workflow | Purpose |
|----------|---------|
| Investigation | Full alert investigation pipeline |
| Entity Extraction | Extract IOCs and entities from alert data |
| Detection | Pattern mining and Sigma rule generation |
| Response | SOAR playbook execution |
| Bootstrap | Seed corpus data loading |
| Entity Graph | Build and query cross-investigation entity relationships |
| Fine-tuning Export | Generate training data from completed investigations |
| Model Evaluation | Run evaluation suites against model versions |
| SRE Self-Healing | Automated failure detection, diagnosis, and patching |
| Validation | Dry-run code execution gate (5s subprocess sandbox) |

### Activities (95)

Activities are individual units of work. Key categories:

| Category | Count | Examples |
|----------|-------|---------|
| LLM Interaction | ~15 | prompt_llm, generate_code, summarize_findings |
| Sandbox Execution | ~8 | execute_sandboxed, validate_ast, apply_seccomp |
| Entity Processing | ~12 | extract_entities, resolve_cross_tenant, score_threat |
| Detection | ~10 | mine_patterns, generate_sigma, validate_sigma |
| Response/SOAR | ~10 | execute_playbook, check_approval, send_notification |
| Data Pipeline | ~10 | export_training_data, score_quality, evaluate_model |
| SRE | ~8 | scan_failures, diagnose, generate_patch, test_patch |
| Reporting | ~6 | generate_report, format_markdown, render_pdf |
| Intelligence | ~6 | analyze_blast_radius, detect_false_positive, deobfuscate |
| Cache/Memory | ~5 | check_cache, store_result, semantic_search |
| Cost/Metrics | ~5 | calculate_cost, log_llm_call, track_tokens |

### Key Modules

| Module | Location | Purpose |
|--------|----------|---------|
| `model_config.py` | `worker/` | 3-tier model routing: hydra-fast, hydra-standard, hydra-reasoning |
| `prompt_registry.py` | `worker/` | SHA256-based prompt version tracking (16 registered prompts) |
| `llm_logger.py` | `worker/` | Non-blocking async LLM call logging to `llm_call_log` table |
| `context_manager.py` | `worker/` | Model-aware context window management (head/tail truncation) |
| `cost_calculator.py` | `worker/` | Per-model cost calculation (19 model entries) |
| `investigation_cache.py` | `worker/` | SHA-256 indicator cache with 24h TTL |
| `investigation_memory.py` | `worker/` | Two-pass enrichment: exact match + pgvector semantic search |
| `prompt_init.py` | `worker/` | Prompt registration at worker startup |
| `security/` | `worker/security/` | Injection detector + prompt sanitizer |
| `intelligence/` | `worker/intelligence/` | Blast radius analysis + false positive detection |
| `reporting/` | `worker/reporting/` | Incident report generator (Markdown + PDF) |
| `skills/` | `worker/skills/` | Deobfuscation sandbox skill |
| `detection/` | `worker/detection/` | Sigma rule generation, pattern mining, validation |
| `response/` | `worker/response/` | SOAR playbook execution, 7 action types, approval gates |
| `models/` | `worker/models/` | Model registry, dynamic routing, A/B test support |
| `finetuning/` | `worker/finetuning/` | Training data export, quality scoring, evaluation |
| `sre/` | `worker/sre/` | Self-healing: monitor, diagnose, patch, test, apply |
| `validation/` | `worker/validation/` | Dry-run gate (5s subprocess sandbox) |
| `bootstrap/` | `worker/bootstrap/` | MITRE (691 techniques), CISA KEV (1536), synthetic investigations |
| `prompts/` | `worker/prompts/` | LLM prompt templates (entity extraction, investigation) |

---

## Database Layer

**Engine:** PostgreSQL 16 with pgvector extension
**Connection pooling:** PgBouncer
**Migrations:** 32 files in `migrations/` (001 through 032)

### Table Inventory (~43 tables)

| Category | Tables | Purpose |
|----------|--------|---------|
| **Core** | `tenants`, `users`, `roles`, `permissions` | Multi-tenant identity |
| **Investigation** | `investigations`, `investigation_steps`, `investigation_results` | Investigation lifecycle |
| **Entity Graph** | `entities`, `entity_edges`, `entity_resolutions` | Cross-investigation IOC correlation |
| **Detection** | `sigma_rules`, `detection_patterns` | Generated detection content |
| **Response** | `playbooks`, `playbook_actions`, `playbook_executions`, `approval_gates` | SOAR automation |
| **LLM** | `llm_call_log`, `prompt_versions`, `model_registry`, `ab_tests` | Model management and observability |
| **Security** | `audit_events`, `auth_attempts`, `account_lockouts` | Security audit trail |
| **Feedback** | `investigation_feedback`, `feedback_accuracy` (view) | Quality tracking |
| **Cost** | `investigation_costs` (view), `token_usage` | Financial tracking |
| **Cache** | `investigation_cache` | Indicator result caching |
| **Config** | `tenant_config`, `webhooks`, `integrations`, `retention_policies` | Per-tenant settings |
| **Corpus** | `mitre_techniques`, `cisa_kev`, `synthetic_investigations` | Reference data |
| **Partitioned** | Time-range partitioned tables for high-volume data | Audit, LLM logs |

### Key Schema Patterns

- **Tenant scoping:** Nearly all tables include a `tenant_id` foreign key. All queries are tenant-scoped.
- **pgvector:** `entities` and `investigation_results` tables include `embedding vector(768)` columns for semantic search via the nomic-embed-text-v1.5 model.
- **Table partitioning:** High-volume tables (`audit_events`, `llm_call_log`) use PostgreSQL range partitioning by timestamp.
- **Materialized views:** Cross-tenant entity resolution and threat scoring use materialized views refreshed on schedule.

---

## Dashboard

**Location:** `dashboard/`
**Stack:** React 19 + Vite 7 + Tailwind 4 + TypeScript 5.9

### Features

| Feature | Description |
|---------|-------------|
| Investigation Waterfall | Step-by-step visualization of investigation progress |
| Executive Summary | High-level ribbon with key metrics and sovereignty badges |
| Entity Graph | Visual representation of IOC relationships |
| C2 Beacon Demo | Built-in demo scenario for showcasing platform capabilities |
| Admin Panel | Tenant management, approvals, cost tracking |
| Playbook Builder | Visual SOAR playbook creation |
| SIEM Alerts | Alert ingestion dashboard |
| Timeline | Investigation timeline visualization |
| Dark/Light Mode | Theme toggle |
| Data Flow Badges | Visual indicators for data sovereignty status |

### Key Directories

| Directory | Purpose |
|-----------|---------|
| `dashboard/src/components/` | UI components (Waterfall, StepDetail, ExecutiveSummary, DataFlowBadge) |
| `dashboard/src/demo/` | C2 beacon demo scenario data |

### Demo Credentials

| Field | Value |
|-------|-------|
| Email | `admin@hydra.local` |
| Password | `hydra123` |
| Role | admin |
| Tenant | hydra-dev |

---

## MCP Server

**Location:** `mcp-server/`
**Stack:** TypeScript + Node.js + `@modelcontextprotocol/sdk`

The MCP (Model Context Protocol) server allows external AI assistants (Claude, etc.) to interact with HYDRA programmatically.

### Tools (7)

| Tool | Purpose |
|------|---------|
| `hydra_health` | Check platform health status |
| `hydra_submit_alert` | Submit a security alert for investigation |
| `hydra_query` | Query investigation results |
| `hydra_get_report` | Retrieve investigation reports |
| `hydra_logs` | Fetch platform logs |
| `hydra_trigger_workflow` | Trigger a Temporal workflow |
| `hydra_create_tenant` | Create a new tenant |

### Resources (7)

Expose read-only data for AI assistant consumption: investigation status, entity graphs, detection rules, feedback data, accuracy metrics, cost summaries, and platform configuration.

### Prompts (6)

Pre-built prompt templates for common SOC tasks that external AI assistants can use when interacting with HYDRA.

---

## Infrastructure Services

### Docker Compose Stack (~20 services)

| Service | Image / Build | Port (internal) | Purpose |
|---------|--------------|-----------------|---------|
| `hydra-api` | Build `api/` | 8090 | Go API gateway |
| `hydra-worker` | Build `worker/` | -- | Python Temporal worker |
| `hydra-dashboard` | Build `dashboard/` | 3000 | React frontend |
| `hydra-postgres` | PostgreSQL 16 + pgvector | 5432 | Primary database |
| `hydra-pgbouncer` | PgBouncer | 6432 | Connection pooling |
| `hydra-redis` | Redis 7-alpine | 6379 | Cache + rate limiting (256MB LRU) |
| `hydra-temporal` | Temporal 1.24.2 | 7233 | Workflow engine |
| `hydra-temporal-ui` | Temporal UI | 8080 | Workflow admin UI |
| `hydra-litellm` | LiteLLM | 4000 | LLM gateway / router |
| `hydra-vllm-chat` | vLLM 0.15.1 | 8000 | Chat model inference |
| `hydra-vllm-embed` | vLLM 0.15.1 | 8001 | Embedding inference |
| `hydra-minio` | MinIO | 9000/9001 | S3-compatible object storage |
| `hydra-jaeger` | Jaeger 1.57 | 16686 | Distributed tracing (OTLP) |
| `hydra-nats` | NATS | 4222 | Event streaming |
| `hydra-prometheus` | Prometheus | 9090 | Metrics collection |
| `hydra-grafana` | Grafana | 3001 | Metrics dashboards |
| `hydra-postgres-exporter` | postgres_exporter | -- | PostgreSQL metrics |
| `hydra-redis-exporter` | redis_exporter | -- | Redis metrics |
| `hydra-temporal-exporter` | Custom | -- | Temporal queue depth metrics |
| `hydra-mcp` | Build `mcp-server/` | -- | MCP server |

### GPU Allocation (RTX 3050, 4GB VRAM)

| Model | VRAM Fraction | Estimated Usage |
|-------|--------------|-----------------|
| Qwen2.5-1.5B-Instruct-AWQ (chat) | 0.40 | ~1.6 GB |
| nomic-embed-text-v1.5 (embed) | 0.15 | ~0.6 GB |
| **Total** | **0.55** | **~2.2 GB** |

---

## Network Topology

### v0.10.1 Security Hardening

As of v0.10.1, only two ports are exposed to the host:

| Service | Host Port | Binding |
|---------|-----------|---------|
| Dashboard | 3000 | `127.0.0.1:3000` |
| API Gateway | 8090 | `127.0.0.1:8090` |

All other services communicate exclusively over the `hydra-internal` Docker bridge network. This was a critical security fix -- prior versions exposed PostgreSQL (5432), Redis (6379), Temporal (7233), NATS (4222), LiteLLM (4000), MinIO (9000/9001), and vLLM embedding (8001) to the host.

### Internal Network

```
hydra-internal (Docker bridge)
├── hydra-api ──────────────► hydra-postgres:5432
│                        ├──► hydra-pgbouncer:6432
│                        ├──► hydra-redis:6379
│                        ├──► hydra-temporal:7233
│                        ├──► hydra-nats:4222
│                        └──► hydra-minio:9000
├── hydra-worker ───────────► hydra-postgres:5432
│                        ├──► hydra-redis:6379
│                        ├──► hydra-temporal:7233
│                        ├──► hydra-litellm:4000
│                        └──► hydra-minio:9000
├── hydra-litellm ──────────► hydra-vllm-chat:8000
│                        └──► hydra-vllm-embed:8001
├── hydra-dashboard ────────► hydra-api:8090
├── hydra-temporal ─────────► hydra-postgres:5432
├── hydra-prometheus ───────► all exporters
└── hydra-grafana ──────────► hydra-prometheus:9090
```

---

## Security Architecture

### Defense Layers

```
Layer 0: Network Perimeter
  └─ Only Dashboard (3000) and API (8090) exposed to host
  └─ All infrastructure services internal-only

Layer 1: Authentication
  └─ JWT access tokens (15min expiry)
  └─ Refresh tokens (7d expiry, httpOnly Strict cookie)
  └─ OIDC with JWKS signature verification (RSA, auto-refresh)
  └─ TOTP 2FA enrollment and verification
  └─ Account lockout (5 failed attempts / 30 minutes)
  └─ Auth rate limiting (10 attempts / 15 minutes / IP)

Layer 2: Authorization
  └─ RBAC (admin, analyst, viewer roles)
  └─ Tenant-scoped queries (tenant_id enforced on all data access)
  └─ Per-tenant rate limits (Redis-backed)
  └─ Per-tenant token quotas

Layer 3: Data Protection
  └─ PII masking (9 regex patterns) before LLM submission
  └─ Redis entity map for PII re-association
  └─ SCRAM-SHA-256 for PostgreSQL authentication
  └─ bcrypt password hashing

Layer 4: Sandbox (code execution)
  └─ AST prefilter (block eval, exec, subprocess, socket, ctypes, importlib, __import__)
  └─ seccomp syscall whitelist
  └─ Docker --network=none (complete network isolation)
  └─ 30-second kill timer

Layer 5: Audit
  └─ All mutating API calls logged to audit_events table
  └─ Structured JSON logging throughout
  └─ Jaeger distributed tracing (OTLP)

Layer 6: LLM Safety
  └─ Injection detection (prompt sanitizer)
  └─ Dry-run validation gate (5s subprocess sandbox)
  └─ Kill switch (global and per-tenant)
  └─ Shadow mode for safe model comparison
```

### CORS Policy

| Setting | Value |
|---------|-------|
| Allowed Origins | `http://localhost:3000` |
| Allowed Methods | GET, POST, PUT, DELETE, OPTIONS |
| Allowed Headers | Authorization, Content-Type |
| Allow Credentials | true |

---

## Authentication & Authorization

### JWT Token Flow

```
Client                    API Gateway              PostgreSQL
  │                           │                        │
  │  POST /auth/login         │                        │
  │  {email, password, totp}  │                        │
  │──────────────────────────►│  Verify bcrypt hash    │
  │                           │───────────────────────►│
  │                           │◄───────────────────────│
  │                           │  Check lockout status  │
  │                           │───────────────────────►│
  │                           │◄───────────────────────│
  │  Set-Cookie: refresh_token│                        │
  │  (httpOnly, Secure,       │  Generate JWT pair     │
  │   SameSite=Strict, 7d)   │                        │
  │  Body: {access_token,15m} │                        │
  │◄──────────────────────────│                        │
  │                           │                        │
  │  GET /api/investigations  │                        │
  │  Cookie: refresh_token    │                        │
  │  Authorization: Bearer AT │                        │
  │──────────────────────────►│  Validate JWT          │
  │                           │  Check signing method  │
  │                           │  Extract tenant_id     │
  │                           │  Check RBAC            │
  │  200 OK (tenant-scoped)  │                        │
  │◄──────────────────────────│                        │
```

### JWT Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| `JWT_SECRET` | env var | Minimum 32 characters; server fatal on weak secret |
| Access token expiry | 15 minutes | Short-lived for security |
| Refresh token expiry | 7 days | Stored in httpOnly Strict cookie |
| Signing algorithm | HS256 | Signing method validated on verification |

### OIDC Integration

| Parameter | Description |
|-----------|-------------|
| `OIDC_ISSUER_URL` | Identity provider URL (e.g., Keycloak, Okta) |
| `OIDC_CLIENT_ID` | Application client ID |
| `OIDC_CLIENT_SECRET` | Application client secret |
| JWKS | RSA key verification with auto-refresh |
| Validation | Issuer + audience claims verified |

### Account Lockout

| Parameter | Value |
|-----------|-------|
| Max failed attempts | 5 |
| Lockout window | 30 minutes |
| Auth rate limit | 10 requests / 15 minutes / IP |

---

## Sandbox Execution

The sandbox provides four layers of defense for executing LLM-generated Python code.

### Execution Pipeline

```
LLM generates Python code
         │
         ▼
┌─────────────────────┐
│  1. AST Prefilter   │  Static analysis of Python AST
│                     │  Blocks: eval, exec, subprocess,
│                     │  socket, ctypes, importlib,
│                     │  __import__
└─────────┬───────────┘
          │ PASS
          ▼
┌─────────────────────┐
│  2. seccomp Profile │  Syscall whitelist/blacklist
│                     │  (sandbox/seccomp_profile.json)
└─────────┬───────────┘
          │ APPLY
          ▼
┌─────────────────────┐
│  3. Docker Container│  --network=none
│                     │  No filesystem mounts
│                     │  Read-only rootfs
└─────────┬───────────┘
          │ RUN
          ▼
┌─────────────────────┐
│  4. Kill Timer      │  30-second hard timeout
│                     │  (sandbox/kill_timer.py)
└─────────┬───────────┘
          │ COMPLETE / KILLED
          ▼
     Return results
```

### Blocked Python Constructs

| Construct | Risk |
|-----------|------|
| `eval()` / `exec()` | Arbitrary code execution |
| `subprocess` | Shell command execution |
| `socket` | Network access |
| `ctypes` | FFI / native code |
| `importlib` | Dynamic module loading |
| `__import__()` | Dynamic import bypass |

### Key Files

| File | Purpose |
|------|---------|
| `sandbox/ast_prefilter.py` | Python AST security validator |
| `sandbox/seccomp_profile.json` | Syscall whitelist/blacklist |
| `sandbox/kill_timer.py` | 30-second execution timeout enforcer |

---

## LLM Routing

### Architecture

```
Worker ──► LiteLLM (port 4000) ──► vLLM Chat (port 8000)
                                └──► vLLM Embed (port 8001)
                                └──► Groq (cloud fallback)
                                └──► OpenRouter (cloud fallback)
                                └──► Anthropic (cloud fallback)
                                └──► OpenAI (cloud fallback)
                                └──► Ollama (air-gap fallback)
```

### Model Tiers

| Tier | Model Name | Use Case | Primary Backend |
|------|-----------|----------|-----------------|
| **Fast** | `hydra-fast` | Quick triage, entity extraction | vLLM: Qwen2.5-1.5B-Instruct-AWQ |
| **Standard** | `hydra-standard` | Full investigations | Cloud fallback chain |
| **Reasoning** | `hydra-reasoning` | Complex analysis, report generation | Cloud fallback chain |

### LiteLLM Model Aliases

| Alias | Target |
|-------|--------|
| `fast` | vLLM chat model (Qwen2.5-1.5B-Instruct-AWQ) |
| `embed` | vLLM embed model (nomic-embed-text-v1.5, 768 dimensions) |

### Fallback Chain (Standard/Reasoning tiers)

```
Groq ──► OpenRouter ──► Anthropic ──► OpenAI ──► Ollama (air-gap)
```

Each provider is tried in order. If all cloud providers fail and Ollama is configured, it serves as the final fallback for air-gapped environments.

### LiteLLM Authentication

| Setting | Value |
|---------|-------|
| Master Key | `sk-hydra-dev-2026` (set via `LITELLM_MASTER_KEY`) |

### Prompt Management

- **16 registered prompts** tracked via SHA256 hash (first 12 chars)
- Prompt versions stored in database for reproducibility
- Registered at worker startup via `prompt_init.py`

### Cost Tracking

- 19 model entries in `cost_calculator.py`
- Per-investigation cost roll-ups via `investigation_costs` view
- Token usage tracked per LLM call in `llm_call_log` table

---

## Data Flow

### Alert Investigation (end-to-end)

```
1. SIEM Alert arrives via webhook
         │
         ▼
2. Go API validates auth, tenant, rate limit
         │
         ▼
3. API writes alert to PostgreSQL
         │
         ▼
4. API starts Temporal workflow (Investigation)
         │
         ▼
5. Worker picks up workflow from Temporal queue
         │
         ▼
6. Worker checks investigation_cache (SHA-256 of indicator)
         │
         ├── CACHE HIT: return cached result (24h TTL)
         │
         └── CACHE MISS: continue
                  │
                  ▼
7. Worker queries investigation_memory
   (exact match + pgvector semantic search)
         │
         ▼
8. Worker masks PII (9 regex patterns)
         │
         ▼
9. Worker checks for prompt injection
         │
         ▼
10. Worker sends prompt to LiteLLM (model tier selection)
         │
         ▼
11. LLM generates investigation code
         │
         ▼
12. Dry-run validation gate (5s subprocess sandbox)
         │
         ▼
13. AST prefilter validates code safety
         │
         ▼
14. Code executes in sandboxed Docker container
    (seccomp + network=none + 30s kill timer)
         │
         ▼
15. Worker extracts entities from results
         │
         ▼
16. Worker updates entity graph
    (entities, edges, cross-tenant resolution)
         │
         ▼
17. Worker calculates cost, logs LLM call
         │
         ▼
18. Worker generates incident report (Markdown/PDF)
         │
         ▼
19. Results stored in PostgreSQL + MinIO (artifacts)
         │
         ▼
20. NATS event published for real-time notification
         │
         ▼
21. Dashboard receives update, renders waterfall
```

### Entity Resolution Flow

```
Investigation Results
         │
         ▼
Entity Extraction (LLM)
  ├── IPs, domains, hashes, users, emails
         │
         ▼
Entity Graph Storage
  ├── entities table (with 768-dim embeddings)
  ├── entity_edges table (relationships)
         │
         ▼
Cross-Tenant Resolution
  ├── Materialized views for privacy-safe intelligence
  ├── Threat scoring based on cross-tenant frequency
         │
         ▼
Blast Radius Analysis
  └── Connected component analysis for impact assessment
```

---

## Configuration & Environment

### Required Environment Variables

| Variable | Description | Notes |
|----------|-------------|-------|
| `JWT_SECRET` | JWT signing key | **Minimum 32 characters.** Server refuses to start if shorter. |
| `DATABASE_URL` | PostgreSQL connection string | Used by API and Worker |
| `POSTGRES_PASSWORD` | PostgreSQL password | SCRAM-SHA-256 authentication |
| `LITELLM_MASTER_KEY` | LiteLLM API key | Default: `sk-hydra-dev-2026` |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq cloud LLM provider | -- |
| `OPENROUTER_API_KEY` | OpenRouter cloud LLM provider | -- |
| `ANTHROPIC_API_KEY` | Anthropic cloud LLM provider | -- |
| `OPENAI_API_KEY` | OpenAI cloud LLM provider | -- |
| `OIDC_ISSUER_URL` | OIDC identity provider URL | -- |
| `OIDC_CLIENT_ID` | OIDC client ID | -- |
| `OIDC_CLIENT_SECRET` | OIDC client secret | -- |
| `VAULT_ADDR` | HashiCorp Vault address | -- |
| `VAULT_TOKEN` | HashiCorp Vault token | -- |
| `NATS_URL` | NATS server URL | `nats://hydra-nats:4222` |

### Configuration Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Full service stack definition (~20 services) |
| `.env` | Development credentials (not committed) |
| `litellm_config.yaml` | LLM routing configuration |
| `litellm_config_rtx3050.yaml` | RTX 3050 GPU-optimized variant |
| `temporal-config/` | Temporal dynamic configuration |
| `monitoring/prometheus.yml` | Prometheus scrape configuration |
| `monitoring/alert_rules.yml` | Prometheus alert rules (6 rules) |

---

## Dependencies

### Go API (`api/`)

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/gin-gonic/gin` | 1.9.1 | HTTP framework |
| `github.com/golang-jwt/jwt/v5` | 5.3.1 | JWT creation and validation |
| `github.com/jackc/pgx/v5` | 5.5.3 | PostgreSQL driver |
| `go.temporal.io/sdk` | 1.25.1 | Temporal workflow client |
| `golang.org/x/crypto` | 0.21.0 | bcrypt password hashing |

### Python Worker (`worker/`)

| Package | Purpose |
|---------|---------|
| `temporalio` | Temporal workflow/activity SDK |
| `psycopg2` | PostgreSQL driver |
| `redis` | Redis client |
| `litellm` | LLM provider abstraction |
| `structlog` | Structured JSON logging |

### Dashboard (`dashboard/`)

| Package | Version | Purpose |
|---------|---------|---------|
| React | 19 | UI framework |
| Vite | 7 | Build tool and dev server |
| Tailwind CSS | 4 | Utility-first CSS |
| TypeScript | 5.9 | Type safety |

### MCP Server (`mcp-server/`)

| Package | Purpose |
|---------|---------|
| `@modelcontextprotocol/sdk` | MCP protocol implementation |
| TypeScript + Node.js | Runtime |

---

## Testing

### Current Test Coverage

| Test Type | Scope | Location |
|-----------|-------|----------|
| **Flake8 Lint** | Python code quality | CI workflow |
| **Core Imports** | Python module import validation | CI workflow |
| **Migration Validation** | SQL migration syntax and ordering | CI workflow |
| **Docker Build** | Service container build verification | CI workflow |
| **Accuracy Suite** | 50 labeled alerts against investigation output | `worker/tests/accuracy/` |
| **Integration Tests** | Cross-service interaction tests | `tests/integration/` |
| **Test Harness** | 20 harness + 5 integration scenarios | `scripts/` |
| **Air-gap Tests** | Ollama fallback verification | `scripts/test-airgap.sh` |

### CI Workflows

The CI pipeline runs on push and pull request events:

1. **Lint:** flake8 across all Python files
2. **Import Test:** Verify all Python modules can be imported
3. **Migration Check:** Validate SQL migration files
4. **Docker Build:** Build all service containers

### Known Test Gaps

| Gap | Impact | Risk |
|-----|--------|------|
| **No Go unit tests** | API endpoint logic untested | High -- regressions in auth, RBAC, tenant scoping |
| **No E2E browser tests** | Dashboard functionality untested | Medium -- UI regressions undetected |
| **No load test in CI** | Performance regressions undetected | Medium -- baseline is 17 inv/min single worker |

---

## Deployment

### Local Development (Docker Compose)

```bash
# Prerequisites
# - Docker with Compose V2
# - NVIDIA GPU with drivers (for local inference)
# - 4GB+ VRAM (RTX 3050 or equivalent)

# 1. Download models
pip install huggingface-hub
huggingface-cli download Qwen/Qwen2.5-1.5B-Instruct-AWQ --local-dir local_models/chat-model
huggingface-cli download nomic-ai/nomic-embed-text-v1.5 --local-dir local_models/embed-model

# 2. Configure environment
cp .env.example .env  # Edit with your values
# Ensure JWT_SECRET is at least 32 characters

# 3. Start stack
docker compose up -d

# 4. Verify health
docker compose ps
curl http://localhost:8090/health
```

### Kubernetes (Kustomize)

**Location:** `k8s/`

Three overlay configurations:

| Overlay | Purpose |
|---------|---------|
| `dev` | Development environment, single replicas |
| `prod` | Production with HPA (2-50 workers), resource limits |
| `airgap` | Air-gapped environment with Ollama, no external network |

Features:
- HPA autoscaling: 2-50 worker replicas based on CPU and Temporal queue depth
- NetworkPolicy enforcement
- Kustomize base + overlays pattern

### Air-Gap Deployment

For fully disconnected environments:

```bash
# Pull Ollama models before going offline
./scripts/airgap-setup.sh

# Verify air-gap mode
./scripts/test-airgap.sh
```

---

## Known Gaps

| Area | Gap | Severity |
|------|-----|----------|
| Testing | No Go unit tests | High |
| Testing | No E2E browser tests | Medium |
| Testing | No load testing in CI | Medium |
| Security | CORS allows only localhost (needs config for production domains) | Low |
| Deployment | K8s manifests validated but not cluster-tested | Medium |
| LLM | Qwen 1.5B has limited reasoning capability vs larger models | Accepted (VRAM constraint) |
| Documentation | OpenAPI spec may be stale | Low |

---

## Directory Reference

```
hydra-mvp/
├── api/                          # Go API gateway (27 .go files, ~58 endpoints)
├── worker/                       # Python Temporal worker (39+ files)
│   ├── bootstrap/                #   MITRE/CISA data + synthetic investigations
│   ├── detection/                #   Sigma rule generation + pattern mining
│   ├── finetuning/               #   Training data export + quality scoring
│   ├── intelligence/             #   Blast radius + FP analysis
│   ├── models/                   #   Model registry + A/B routing
│   ├── prompts/                  #   LLM prompt templates
│   ├── reporting/                #   Incident report generation (MD + PDF)
│   ├── response/                 #   SOAR playbook execution
│   ├── security/                 #   Injection detection + sanitization
│   ├── skills/                   #   Deobfuscation sandbox skill
│   ├── sre/                      #   Self-healing SRE agent
│   ├── tests/accuracy/           #   50 labeled alerts + validation runner
│   └── validation/               #   Dry-run execution gate
├── dashboard/                    # React 19 + Vite 7 + Tailwind 4 SPA
│   └── src/
│       ├── components/           #   UI components
│       └── demo/                 #   C2 beacon demo data
├── sandbox/                      # AST prefilter + seccomp + kill timer
├── mcp-server/                   # MCP server (TypeScript, 7 tools)
├── migrations/                   # SQL migrations 001-032
├── k8s/                          # Kubernetes manifests (Kustomize)
│   ├── base/                     #   Base resources
│   └── overlays/                 #   dev / prod / airgap
├── monitoring/                   # Prometheus + Grafana + alert rules
├── scripts/                      # Load testing, seed data, test harness
├── tests/                        # Integration tests, test corpus
│   ├── corpus/                   #   5 threat categories x 4 difficulties
│   └── integration/              #   Cross-service tests
├── temporal-config/              # Temporal dynamic configuration
├── local_models/                 # Downloaded model weights
│   ├── chat-model/               #   Qwen2.5-1.5B-Instruct-AWQ
│   └── embed-model/              #   nomic-embed-text-v1.5
├── demo/                         # Demo scenarios (3 MSSP types)
├── docs/                         # Architecture, deployment, guides
├── docker-compose.yml            # ~20-service stack
├── litellm_config.yaml           # LLM routing config
└── litellm_config_rtx3050.yaml   # RTX 3050 variant
```

---

## Performance Benchmarks

| Metric | Single Worker | Multi-Worker | Notes |
|--------|--------------|--------------|-------|
| Investigation throughput | 17 inv/min | 21 inv/min | Baseline load test |
| Stress test | -- | 100 concurrent tasks | Completed successfully |
| K8s HPA range | -- | 2-50 replicas | Based on CPU + queue depth |

---

## Monitoring & Observability

### Stack

| Service | Port | Purpose |
|---------|------|---------|
| Prometheus | 9090 (internal) | Metrics collection and alerting |
| Grafana | 3001 (internal) | 3 dashboards for visualization |
| Jaeger | 16686 (internal) | Distributed tracing (OTLP) |
| postgres_exporter | internal | PostgreSQL metrics |
| redis_exporter | internal | Redis metrics |
| temporal_exporter | internal | Temporal queue depth + worker metrics |

### Alert Rules (6)

Prometheus alert rules configured in `monitoring/alert_rules.yml` covering service health, resource utilization, and SLA thresholds.

### Grafana Dashboards (3)

Pre-configured dashboards for infrastructure health, investigation pipeline metrics, and LLM performance tracking.

---

*Document generated for HYDRA v0.10.1 (commit f1974bd, 2026-03-13).*
