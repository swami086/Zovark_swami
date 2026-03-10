# HYDRA Codebase Architecture -- Complete Reference
## Generated: 2026-03-10
## Repo: C:\Users\vinay\Desktop\HYDRA\hydra-mvp
## Branch: master

---

## Table of Contents

1. [Repository Structure](#1-repository-structure)
2. [Git History](#2-git-history-32-commits)
3. [Docker Services](#3-docker-services)
4. [Database Schema](#4-database-schema)
5. [Go API Endpoints](#5-go-api-endpoints-42-endpoints)
6. [Python Worker](#6-python-worker)
7. [LLM Configuration](#7-llm-configuration)
8. [MCP Server](#8-mcp-server)
9. [Dashboard](#9-dashboard)
10. [Kubernetes Manifests](#10-kubernetes-manifests)
11. [Migration History](#11-migration-history-001-019)
12. [Environment Variables](#12-environment-variables)
13. [Live Data Summary](#13-live-data-summary)
14. [Development Conventions](#14-development-conventions)
15. [Known Issues and Gaps](#15-known-issues-and-gaps)

---

## 1. Repository Structure

### Top-Level Directories

| Directory | Purpose |
|-----------|---------|
| `api/` | Go API gateway (Gin framework, port 8090) |
| `worker/` | Python Temporal worker (7 workflows, 58 activities) |
| `dashboard/` | React 19 + Vite 7 + Tailwind 4 + TypeScript 5.9 |
| `mcp-server/` | MCP server (TypeScript, @modelcontextprotocol/sdk) |
| `sandbox/` | Security layers (AST prefilter, seccomp, kill timer) |
| `k8s/` | Kubernetes deployment (Kustomize + 3 overlays) |
| `migrations/` | SQL migrations (001-019) |
| `monitoring/` | Prometheus, alert rules, exporters |
| `scripts/` | Load testing, seed data, utilities |
| `tests/` | Integration tests, corpus, accuracy validation |
| `docs/` | Architecture docs, benchmarks, guides |
| `config/` | PostgreSQL config (postgresql.conf, pg_hba.conf) |
| `temporal-config/` | Temporal dynamic config |
| `local_models/` | LLM weights (chat + embed) |
| `demo/` | Demo scenarios |
| `files/` | Sprint prompts and architecture docs |

### Key Root Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | 18-service stack orchestration |
| `init.sql` | Complete DB schema (~1100 lines) |
| `litellm_config.yaml` | 3-tier LLM routing with fallbacks |
| `.env.example` | Environment variables template |
| `.gitattributes` | LF line ending enforcement |
| `.editorconfig` | Editor config (LF, UTF-8) |
| `.github/workflows/ci.yml` | CI/CD pipeline |

### Complete File Listing (~200 files)

```
api/                         12 Go source files + Dockerfile + go.mod/sum
worker/                      58+ Python files across 12 subdirectories + Dockerfile + requirements.txt
dashboard/src/               29 files (6 pages, 10 components, 1 hook, 1 demo, 1 API client, 1 types)
mcp-server/src/              4 TypeScript files (index.ts, api.ts, db.ts, exec.ts)
sandbox/                     3 files (ast_prefilter.py, seccomp_profile.json, kill_timer.py)
k8s/                         31 manifest files (base + 3 overlays)
migrations/                  19 SQL files (001-019)
monitoring/                  4 files (prometheus.yml, alert_rules.yml, temporal_exporter.py, worker_metrics.py)
scripts/                     17 files (seed data, load testing, airgap, bootstrap)
tests/                       12 files (corpus, integration, unit, load test results)
docs/                        12 documentation files
config/                      2 files (postgresql.conf, pg_hba.conf)
temporal-config/             1 file (development-sql.yaml)
local_models/                2 directories (chat-model, embed-model) with weights
demo/                        1 file (scenarios.json)
```

---

## 2. Git History (32 commits)

```
6b87875 Sprint 7: Enterprise features -- executive dashboard, air-gap, feedback, cost tracking, cache, accuracy framework
ea7ca8d Sprint 6: Investigation dashboard -- waterfall visualization + C2 beacon demo mode
ac0572f Sprint 5: LLM reliability, dry-run validation, investigation memory, alert dedup
7c6bd0c Sprint 4C: Hydra MCP Server -- 7 tools for AI-powered platform operation
8efdb4f Sprint 4A: Self-healing SRE agent -- failure scan, diagnosis, patching, testing, application
25c8fe7 docs: RCA for lint debt + .gitattributes + .editorconfig for line ending enforcement
88f2c26 fix: resolve flake8 lint errors for CI
58705c4 Sprint 3F: Security hardening -- audit middleware, rate limiting, data retention, account lockout
22ffc71 Sprint 3E: Model registry + A/B testing + dynamic routing
9ee289f Sprint 3D: Fine-tuning data pipeline -- training export, quality scoring, model evaluation
e4766b1 Sprint 3C: Tenant onboarding + webhook integrations + per-tenant rate limits
81a1359 Sprint 3B: Observability stack -- Prometheus + Grafana + exporters + alert rules
556f691 Sprint 3A: Production fixes -- CI/CD pipeline, health endpoint, structured logging
80ab2e5 docs: Final MVP audit report -- all 13 sprints complete
6054579 Sprint 2B: SOAR response playbooks -- 7 action types, 5 default playbooks, auto-trigger
c798ae5 Sprint 2A: Self-generating detection engine -- pattern mining + Sigma rule generation
abf5fe1 Sprint 1J: Lease-based rate limiting + KEDA autoscaling + Temporal queue depth exporter
45cdc2e Sprint 1I: Model tiering + prompt versioning + LLM call logging
ea838d2 Sprint 1K: Cross-tenant entity resolution -- materialized views, threat scoring
70c26ac docs: Hydra architecture reference document
f0a99f7 Sprint 1H: Bootstrap entity graph at scale -- 100 synthetic investigations, 240 entities
5a9ac30 Sprint 1L: Golden Path -- blast radius, deobfuscation, incident reports, FP confidence
59753e0 Sprint 1F: Bootstrap corpus -- MITRE ATT&CK (691 techniques) + CISA KEV (1536 vulns)
e433104 Sprint 1E: Production hardening -- sandbox limits, SCRAM-SHA-256, audit events
e60bbd3 Sprint 1G: Entity graph schema -- investigations, entities, edges, observations
f52f070 Block 1.5: K8s deployment verification
0fd15af Block 1.4b: Kubernetes manifests -- Kustomize + HPA + NetworkPolicy
986809f Block 1.4a: Load testing -- baseline 17inv/min, scaled 21inv/min, stress 100 tasks
fb76387 Block 1.3: PgBouncer + Postgres tuning + Redis rate limiting + table partitioning
329aac3 Block 1.2: Multi-worker scaling
74931d6 Block 1.1: Stateless worker + worker identity tracking
9d7c691 Sprint 12: 20/20 harness + 5/5 integration - test framework complete
```

---

## 3. Docker Services

| Service | Image | Container Name | Ports | Profiles | Key Config |
|---------|-------|---------------|-------|----------|------------|
| postgres | pgvector/pgvector:pg16 | hydra-postgres | 5432 | (default) | pgvector enabled, custom postgresql.conf, SCRAM-SHA-256 |
| redis | redis:7-alpine | hydra-redis | 6379 | (default) | maxmemory 256mb, allkeys-lru |
| pgbouncer | edoburu/pgbouncer | hydra-pgbouncer | - | (default) | transaction pooling, max 400 clients, 50 DB conns |
| temporal | temporalio/auto-setup:1.24.2 | hydra-temporal | 7233 | (default) | postgres-backed, dynamic config |
| temporal-ui | temporalio/ui:2.26.2 | hydra-temporal-ui | 8080 | debug | Web UI for Temporal |
| litellm | litellm-database:main-stable | hydra-litellm | 4000 | (default) | 3-tier model routing, 4 API keys |
| minio | minio/minio:latest | hydra-minio | 9000, 9001 | storage | S3-compatible storage |
| embedding-server | text-embeddings-inference:cpu-1.2 | hydra-embedding | 8081 | (default) | BAAI/bge-base-en-v1.5, CPU mode |
| jaeger | jaegertracing/all-in-one:1.57 | hydra-jaeger | 16686, 4317, 4318 | monitoring | OTLP tracing |
| ollama | ollama/ollama:latest | hydra-ollama | 11434 | airgap | Local LLM for air-gapped operation |
| api | ./api Dockerfile | hydra-api | 8090 | (default) | Go API, JWT auth, PgBouncer connection |
| worker | ./worker Dockerfile | (no name, scalable) | - | (default) | Python worker, Docker socket mount |
| dashboard | ./dashboard Dockerfile | hydra-dashboard | 3000 | (default) | React app served via nginx |
| temporal-exporter | ./worker (custom cmd) | hydra-temporal-exporter | 9092 | monitoring | Temporal metrics for Prometheus |
| prometheus | prom/prometheus:v2.51.0 | hydra-prometheus | 9090 | monitoring | 7d retention, alert rules |
| grafana | grafana/grafana:10.4.1 | hydra-grafana | 3001 | monitoring | 3 dashboards, admin/hydra |
| postgres-exporter | postgres-exporter:v0.15.0 | hydra-postgres-exporter | 9187 | monitoring | PostgreSQL metrics |
| redis-exporter | redis_exporter:v1.58.0 | hydra-redis-exporter | 9121 | monitoring | Redis metrics |
| worker-metrics | ./worker (custom cmd) | hydra-worker-metrics | 9093 | monitoring | Worker metrics for Prometheus |

### Service Port Summary

| Port | Service | URL |
|------|---------|-----|
| 3000 | Dashboard | http://localhost:3000 |
| 3001 | Grafana | http://localhost:3001 |
| 4000 | LiteLLM | http://localhost:4000 |
| 5432 | PostgreSQL | - |
| 6379 | Redis | - |
| 7233 | Temporal | - |
| 8080 | Temporal UI | http://localhost:8080 |
| 8081 | Embedding Server | (internal) |
| 8090 | API Gateway | http://localhost:8090 |
| 9000 | MinIO API | - |
| 9001 | MinIO Console | http://localhost:9001 |
| 9090 | Prometheus | http://localhost:9090 |
| 9092 | Temporal Exporter | (internal) |
| 9093 | Worker Metrics | (internal) |
| 9121 | Redis Exporter | (internal) |
| 9187 | Postgres Exporter | (internal) |
| 11434 | Ollama | (airgap only) |
| 16686 | Jaeger UI | http://localhost:16686 |

### Docker Profiles

| Profile | Services Activated |
|---------|-------------------|
| (default) | postgres, redis, pgbouncer, temporal, litellm, embedding-server, api, worker, dashboard |
| debug | temporal-ui |
| storage | minio |
| monitoring | jaeger, temporal-exporter, prometheus, grafana, postgres-exporter, redis-exporter, worker-metrics |
| airgap | ollama |

---

## 4. Database Schema

### Overview

- **41 base tables, 67 total with partitions**
- PostgreSQL 16 with pgvector extension
- 3 materialized views, 3 views
- Partitioned tables: `investigations` (12 monthly + default), `audit_events` (12 monthly + default)

### Core Tables

**tenants**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| name | TEXT | NOT NULL |
| slug | TEXT | UNIQUE |
| tier | TEXT | |
| max_concurrent | INT | |
| settings | JSONB | |
| created_at | TIMESTAMPTZ | |

**users**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK -> tenants |
| email | TEXT | UNIQUE |
| display_name | TEXT | |
| role | TEXT | CHECK(admin/analyst/viewer) |
| password_hash | TEXT | |
| failed_login_attempts | INT | |
| locked_until | TIMESTAMPTZ | |
| created_at | TIMESTAMPTZ | |

**agent_tasks**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK -> tenants |
| prompt | TEXT | |
| code | TEXT | |
| result | JSONB | |
| risk_level | TEXT | |
| status | TEXT | CHECK(pending/executing/completed/failed) |
| task_type | TEXT | |
| severity | TEXT | |
| workflow_id | TEXT | |
| worker_id | TEXT | |
| created_at | TIMESTAMPTZ | |
| completed_at | TIMESTAMPTZ | |

**agent_task_steps**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| task_id | UUID | FK -> agent_tasks |
| step_number | INT | |
| step_name | TEXT | |
| status | TEXT | |
| input_data | JSONB | |
| output_data | JSONB | |
| error_message | TEXT | |
| duration_ms | INT | |
| started_at | TIMESTAMPTZ | |
| completed_at | TIMESTAMPTZ | |

**agent_skills**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| name | TEXT | |
| skill_slug | TEXT | |
| version | INT | |
| description | TEXT | |
| system_prompt | TEXT | |
| expected_entity_types | TEXT[] | |
| mitre_techniques | TEXT[] | |
| threat_types | TEXT[] | |
| keywords | TEXT[] | |
| embedding | vector(768) | |
| is_active | BOOL | |
| created_at | TIMESTAMPTZ | |

**approval_requests**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| task_id | UUID | FK -> agent_tasks |
| risk_level | TEXT | |
| status | TEXT | CHECK(pending/approved/rejected/timeout) |
| requested_at | TIMESTAMPTZ | |
| decided_at | TIMESTAMPTZ | |
| decided_by | UUID | FK -> users |
| reason | TEXT | |

### Investigation / Entity Graph Tables

**investigations** (PARTITIONED BY RANGE created_at)
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | Composite PK (id, created_at) |
| created_at | TIMESTAMPTZ | Composite PK |
| tenant_id | UUID | FK -> tenants |
| task_id | UUID | |
| alert_source | TEXT | |
| alert_type | TEXT | |
| skill_id | UUID | FK -> agent_skills |
| attack_techniques | TEXT[] | |
| verdict | TEXT | CHECK(true_positive/false_positive/benign/suspicious/inconclusive) |
| risk_score | INT | 0-100 |
| confidence | FLOAT | 0.0-1.0 |
| timeline | JSONB | |
| summary | TEXT | |
| summary_embedding | vector(768) | |
| source | TEXT | CHECK(production/bootstrap/synthetic) |
| injection_detected | BOOL | |

Partitions: `investigations_2026_01` through `investigations_2026_12` + `investigations_default`

**entities**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| entity_type | TEXT | CHECK(ip/domain/file_hash/url/email/user/process/device) |
| value | TEXT | |
| normalized_value | TEXT | |
| entity_hash | VARCHAR(64) | |
| threat_score | INT | 0-100 |
| first_seen | TIMESTAMPTZ | |
| last_seen | TIMESTAMPTZ | |
| metadata | JSONB | |

**entity_edges**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| source_entity_id | UUID | FK -> entities |
| target_entity_id | UUID | FK -> entities |
| edge_type | TEXT | CHECK(communicates_with/resolves_to/...) |
| investigation_id | UUID | |
| mitre_technique | TEXT | |
| confidence | FLOAT | |
| metadata | JSONB | |
| created_at | TIMESTAMPTZ | |

**entity_observations**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| entity_id | UUID | FK -> entities |
| investigation_id | UUID | |
| tenant_id | UUID | FK |
| role | TEXT | CHECK(source/destination/indicator/tool/victim) |
| confidence_source | TEXT | CHECK(llm/sandbox/rule/manual) |
| mitre_technique | TEXT | |
| context | JSONB | |
| observed_at | TIMESTAMPTZ | |

**investigation_steps**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| task_id | UUID | FK -> agent_tasks |
| step_number | INT | |
| step_type | TEXT | |
| input_data | JSONB | |
| output_data | JSONB | |
| model_used | TEXT | |
| prompt_version | TEXT | |
| tokens_used | INT | |
| duration_ms | INT | |
| status | TEXT | |
| error_message | TEXT | |
| created_at | TIMESTAMPTZ | |

**investigation_memory**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| entity_type | TEXT | |
| entity_value | TEXT | |
| entity_hash | TEXT | |
| investigation_id | UUID | |
| outcome | TEXT | |
| confidence | FLOAT | |
| embedding | vector(768) | |
| created_at | TIMESTAMPTZ | |

**investigation_reports**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| investigation_id | UUID | |
| tenant_id | UUID | FK |
| report_format | TEXT | CHECK(markdown/pdf/json) |
| content | TEXT | |
| metadata | JSONB | |
| created_at | TIMESTAMPTZ | |

**investigation_feedback**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| investigation_id | UUID | |
| tenant_id | UUID | FK |
| analyst_id | UUID | FK -> users |
| verdict_correct | BOOL | |
| corrected_verdict | TEXT | |
| false_positive | BOOL | |
| missed_threat | BOOL | |
| notes | TEXT | |
| analyst_confidence | FLOAT | |
| created_at | TIMESTAMPTZ | |

**investigation_cache**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| cache_key | VARCHAR(64) | UNIQUE |
| investigation_id | UUID | |
| task_id | UUID | |
| verdict | TEXT | |
| risk_score | INT | |
| confidence | FLOAT | |
| entity_count | INT | |
| summary | TEXT | |
| ttl_hours | INT | DEFAULT 24 |
| created_at | TIMESTAMPTZ | |
| expires_at | TIMESTAMPTZ | |

### Detection Engine Tables

**detection_candidates**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| pattern_signature | TEXT | UNIQUE |
| technique_id | VARCHAR(20) | FK -> mitre_techniques |
| pattern_type | TEXT | |
| entity_patterns | JSONB | |
| edge_patterns | TEXT[] | |
| investigation_count | INT | |
| tenant_spread | INT | |
| avg_risk_score | FLOAT | |
| status | TEXT | CHECK(candidate/generating/validating/approved/deployed/rejected/retired) |
| sigma_rule | TEXT | |
| validation_result | JSONB | |
| created_at | TIMESTAMPTZ | |

**detection_rules**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| candidate_id | UUID | FK -> detection_candidates |
| technique_id | VARCHAR(20) | |
| rule_name | TEXT | |
| rule_version | INT | |
| sigma_yaml | TEXT | |
| status | TEXT | CHECK(active/testing/retired) |
| tp_rate | FLOAT | |
| fp_rate | FLOAT | |
| investigations_matched | INT | |
| tenant_spread | INT | |
| created_at | TIMESTAMPTZ | |
| | | UNIQUE(technique_id, rule_version) |

### Response / SOAR Tables

**response_playbooks**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| name | TEXT | |
| description | TEXT | |
| trigger_conditions | JSONB | |
| actions | JSONB | |
| requires_approval | BOOL | |
| cooldown_minutes | INT | |
| enabled | BOOL | |
| created_at | TIMESTAMPTZ | |

**response_executions**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| playbook_id | UUID | FK -> response_playbooks |
| investigation_id | UUID | |
| trigger_data | JSONB | |
| actions_executed | JSONB | |
| status | TEXT | CHECK(pending/running/completed/failed/approval_required) |
| approval_request_id | UUID | |
| started_at | TIMESTAMPTZ | |
| completed_at | TIMESTAMPTZ | |

**response_integrations**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| name | TEXT | |
| integration_type | TEXT | CHECK(slack/jira/servicenow/pagerduty/email/webhook/firewall) |
| config | JSONB | |
| enabled | BOOL | |
| created_at | TIMESTAMPTZ | |

### LLM / Model Management Tables

**llm_call_log**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | |
| task_id | UUID | |
| activity_name | TEXT | |
| model_tier | TEXT | |
| model_id | TEXT | |
| prompt_name | TEXT | |
| prompt_version | TEXT | |
| input_tokens | INT | |
| output_tokens | INT | |
| estimated_cost_usd | DECIMAL | |
| cost_usd | DECIMAL(10,6) | |
| latency_ms | INT | |
| status | TEXT | |
| error_message | TEXT | |
| temperature | FLOAT | |
| max_tokens | INT | |
| created_at | TIMESTAMPTZ | |

**model_registry**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| name | TEXT | |
| provider | TEXT | |
| model_id | TEXT | |
| tier | TEXT | |
| config | JSONB | |
| is_active | BOOL | |
| created_at | TIMESTAMPTZ | |

**model_ab_tests**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| name | TEXT | |
| model_a_id | UUID | FK -> model_registry |
| model_b_id | UUID | FK -> model_registry |
| traffic_split | FLOAT | |
| metrics | JSONB | |
| status | TEXT | CHECK(active/completed/cancelled) |
| created_at | TIMESTAMPTZ | |
| completed_at | TIMESTAMPTZ | |

**finetuning_jobs**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| model_name | TEXT | |
| dataset_size | INT | |
| training_config | JSONB | |
| metrics | JSONB | |
| status | TEXT | CHECK(queued/exporting/training/evaluating/completed/failed) |
| artifact_path | TEXT | |
| created_at | TIMESTAMPTZ | |
| completed_at | TIMESTAMPTZ | |

### Bootstrap Data Tables

**mitre_techniques**
| Column | Type | Constraints |
|--------|------|-------------|
| id | VARCHAR(20) | PK |
| name | TEXT | |
| tactic | TEXT | |
| description | TEXT | |
| platforms | TEXT[] | |
| data_sources | TEXT[] | |
| is_subtechnique | BOOL | |
| parent_id | VARCHAR(20) | |
| severity | TEXT | |
| detection_notes | TEXT | |
| loaded_at | TIMESTAMPTZ | |

**bootstrap_corpus**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| source | TEXT | CHECK(mitre/cisa_kev/synthetic) |
| source_id | TEXT | |
| title | TEXT | |
| description | TEXT | |
| alert_type | TEXT | |
| severity | TEXT | |
| raw_data | JSONB | |
| investigation_data | JSONB | |
| status | TEXT | CHECK(pending/processed/failed) |
| loaded_at | TIMESTAMPTZ | |

### Security / Audit Tables

**audit_events** (PARTITIONED BY RANGE created_at)
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK (composite with created_at) |
| created_at | TIMESTAMPTZ | PK (composite with id) |
| tenant_id | UUID | FK -> tenants |
| user_id | UUID | |
| event_type | TEXT | CHECK (see below) |
| resource_type | TEXT | |
| resource_id | UUID | |
| metadata | JSONB | |
| ip_address | TEXT | |
| user_agent | TEXT | |

Event types: `investigation_started`, `completed`, `code_executed`, `approval_requested`, `granted`, `denied`, `timeout`, `entity_extracted`, `detection_generated`, `user_login`, `registered`, `injection_detected`, `cross_tenant_hit`, `threat_score_updated`, `self_healing_scan`, `diagnosis`, `patch_applied`, `patch_failed`, `rollback`

Partitions: `audit_events_2026_01` through `audit_events_2026_12` + `audit_events_default`

**data_retention_policies**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| table_name | TEXT | UNIQUE |
| retention_days | INT | |
| archive_before_delete | BOOL | |
| last_run_at | TIMESTAMPTZ | |
| created_at | TIMESTAMPTZ | |

**self_healing_events**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| failure_id | TEXT | |
| workflow_id | TEXT | |
| activity_name | TEXT | |
| error_category | TEXT | CHECK(dependency_missing/logic_bug/llm_malformed/resource_exhaustion/unknown) |
| diagnosis | JSONB | |
| patch_type | TEXT | |
| patch_content | TEXT | |
| test_result | JSONB | |
| applied | BOOL | |
| rolled_back | BOOL | |
| file_path | TEXT | |
| backup_path | TEXT | |
| created_at | TIMESTAMPTZ | |

**alert_fingerprints**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK -> tenants |
| fingerprint | VARCHAR(64) | |
| alert_source | TEXT | |
| alert_type | TEXT | |
| first_seen | TIMESTAMPTZ | |
| last_seen | TIMESTAMPTZ | |
| alert_count | INT | DEFAULT 1 |
| investigation_id | UUID | |
| dedup_window_seconds | INT | DEFAULT 900 |
| raw_sample | JSONB | |
| | | UNIQUE(tenant_id, fingerprint) |

### Webhook / Integration Tables

**webhook_endpoints**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK -> tenants |
| name | TEXT | |
| url | TEXT | |
| secret | VARCHAR(255) | HMAC-SHA256 signing secret |
| event_types | TEXT[] | investigation_completed, alert_received, approval_needed, response_executed |
| is_active | BOOL | |
| created_at | TIMESTAMPTZ | |

**webhook_deliveries**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| endpoint_id | UUID | FK -> webhook_endpoints |
| tenant_id | UUID | FK |
| event_type | TEXT | |
| payload | JSONB | |
| status | TEXT | CHECK(pending/delivered/failed/retrying) |
| http_status | INT | |
| response_body | TEXT | |
| attempts | INT | |
| max_attempts | INT | DEFAULT 3 |
| last_attempt_at | TIMESTAMPTZ | |
| next_retry_at | TIMESTAMPTZ | |
| created_at | TIMESTAMPTZ | |

### SIEM Tables

**siem_alerts**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK -> tenants |
| log_source_id | UUID | FK -> log_sources |
| task_id | UUID | FK -> agent_tasks |
| alert_name | TEXT | |
| severity | VARCHAR(20) | |
| source_ip | VARCHAR(45) | |
| dest_ip | VARCHAR(45) | |
| rule_name | VARCHAR(500) | |
| raw_event | JSONB | |
| normalized_event | JSONB | |
| status | TEXT | CHECK(new/acknowledged/dismissed) |
| auto_investigate | BOOL | |
| created_at | TIMESTAMPTZ | |

**log_sources**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK -> tenants |
| name | TEXT | |
| source_type | VARCHAR(50) | splunk/elastic/generic |
| connection_config | JSONB | webhook_secret, auto_investigate |
| is_active | BOOL | |
| last_event_at | TIMESTAMPTZ | |
| event_count | INT | |
| created_by | UUID | FK -> users |
| created_at | TIMESTAMPTZ | |

### User / Memory Tables

**agent_audit_log** (immutable)
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| user_id | UUID | FK -> users |
| action | TEXT | |
| resource_type | TEXT | |
| resource_id | UUID | |
| details | JSONB | |
| ip_address | INET | |
| user_agent | TEXT | |
| created_at | TIMESTAMPTZ | |

**agent_personas**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| name | TEXT | |
| system_prompt | TEXT | |
| model_name | TEXT | DEFAULT "fast" |
| temperature | FLOAT | CHECK(0-2), DEFAULT 0.7 |
| max_tokens | INT | DEFAULT 2048 |
| tools_enabled | JSONB | |
| is_default | BOOL | |
| created_at | TIMESTAMPTZ | |

**agent_memory_episodic**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| persona_id | UUID | FK -> agent_personas |
| task_id | UUID | FK |
| memory_type | TEXT | CHECK(task_outcome/error_lesson/user_preference/skill_feedback) |
| content | TEXT | |
| embedding | vector(768) | HNSW index |
| importance_score | FLOAT | CHECK(0-1) |
| access_count | INT | |
| last_accessed_at | TIMESTAMPTZ | |
| expires_at | TIMESTAMPTZ | |
| created_at | TIMESTAMPTZ | |

**usage_records** (immutable)
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| user_id | UUID | FK |
| task_id | UUID | FK |
| record_type | TEXT | CHECK(llm_call/embedding/skill_exec/storage) |
| model_name | TEXT | |
| tokens_input | INT | |
| tokens_output | INT | |
| cost_usd | DECIMAL(10,6) | |
| execution_ms | INT | |
| metadata | JSONB | |
| created_at | TIMESTAMPTZ | |

**playbooks**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| name | TEXT | |
| description | TEXT | |
| icon | TEXT | |
| task_type | TEXT | |
| is_template | BOOL | |
| system_prompt_override | TEXT | |
| steps | JSONB | DEFAULT [] |
| created_by | UUID | FK -> users |
| created_at | TIMESTAMPTZ | |

**object_refs**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| bucket | TEXT | |
| object_key | VARCHAR(500) | UNIQUE(bucket, object_key) |
| content_type | TEXT | |
| size_bytes | BIGINT | |
| checksum_sha256 | TEXT | |
| uploaded_by | UUID | FK -> users |
| task_id | UUID | FK |
| created_at | TIMESTAMPTZ | |

**working_memory_snapshots**
| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PK |
| tenant_id | UUID | FK |
| task_id | UUID | FK |
| snapshot_data | JSONB | |
| token_count | INT | |
| created_at | TIMESTAMPTZ | |

### Materialized Views (3)

**cross_tenant_intel**
Cross-tenant entity intelligence aggregation.
Columns: entity_type, value, normalized_value, entity_hash, tenant_count, total_observations, risk_scores, verdicts, first_seen, last_seen

**feedback_accuracy**
Feedback statistics aggregate.
Columns: total, correct, incorrect, false_positives, missed_threats, accuracy_rate, avg_analyst_confidence

**model_performance**
Model performance metrics across all LLM calls.

### Views (3)

**cross_tenant_public**
Privacy-safe cross-tenant intelligence (no raw entity values exposed).

**investigation_costs**
Per-task LLM cost rollup.
Columns: task_id, llm_calls, total_input_tokens, total_output_tokens, total_cost_usd

**v_task_summary**
Task overview combining task metadata with investigation results.

### Indexes (100+)

**Index Strategy by Type:**
- **B-Tree (50+):** Primary/foreign key lookups, composite indexes
- **GIN:** Array searches on keywords, mitre_techniques, threat_types, attack_techniques
- **IVFFlat:** pgvector cosine distance (summary_embedding, mitre_embedding) -- lists=50-100
- **HNSW:** Faster vector neighbor search (investigation_memory, agent_skills, agent_memory_episodic)
- **Partial/Conditional:** WHERE clauses on status, active flags, null checks

**Key Composite Indexes:**
- `idx_agent_tasks_tenant_status` (tenant_id, status)
- `idx_investigations_verdict_source` (verdict, source) WHERE source='production'
- `idx_entity_edges_source_type` (source_entity_id, edge_type)
- `idx_alert_fp_tenant_hash` UNIQUE (tenant_id, fingerprint)

### Constraints

**Immutable Tables (trigger-protected):**
- `audit_events` -- prevent_audit_modification() blocks UPDATE/DELETE
- `agent_audit_log` -- audit_log_immutable blocks UPDATE/DELETE
- `usage_records` -- usage_records_immutable blocks UPDATE/DELETE

**Check Constraints (25+):**
- tenants.tier IN (free, professional, enterprise)
- users.role IN (admin, analyst, viewer)
- agent_tasks.status -- 9 valid statuses
- investigations.verdict -- 5 valid verdicts
- investigations.confidence 0-1, risk_score 0-100
- entity_edges.edge_type -- 11 valid types
- entities.entity_type -- 8 entity types
- audit_events.event_type -- 21 event types
- self_healing_events.error_category -- 5 categories

### Partitioning

| Table | Strategy | Partitions |
|-------|----------|------------|
| investigations | RANGE(created_at) | 12 monthly (2026-01 to 2026-12) + default |
| audit_events | RANGE(created_at) | 12 monthly (2026-01 to 2026-12) + default |

### Live Data (as of 2026-03-10)

| Table | Rows |
|-------|------|
| bootstrap_corpus | 1,636 |
| mitre_techniques | 691 |
| entity_observations | 588 |
| entities | 304 |
| entity_edges | 258 |
| investigations | 138 |
| audit_events | 21 |
| llm_call_log | 16 |
| detection_candidates | 14 |
| detection_rules | 14 |
| agent_tasks | 10 |
| agent_skills | 10 |
| users | 7 |
| response_playbooks | 5 |
| tenants | 4 |
| model_registry | 2 |
| webhook_endpoints | 1 |
| investigation_feedback | 1 |

**Entity type distribution:** domain(77), file_hash(62), process(61), ip(35), device(30), user(22), url(14), email(3)

**Investigation verdicts:** true_positive(124), suspicious(14)

**Task statuses:** completed(5), failed(4), pending(1)

---

## 5. Go API Endpoints (~42 endpoints)

### Auth Routes (public, rate-limited)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| POST | /api/v1/auth/login | loginHandler | None |
| POST | /api/v1/auth/register | registerHandler | None |

### Public Routes

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | /health | healthCheckHandler | None |
| POST | /api/v1/webhooks/:source_id/alert | webhookAlertHandler | HMAC |

### Authenticated (any role)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | /api/v1/tasks | listTasksHandler | JWT |
| GET | /api/v1/tasks/:id | getTaskHandler | JWT |
| GET | /api/v1/tasks/:id/audit | getTaskAuditHandler | JWT |
| GET | /api/v1/tasks/:id/steps | getTaskStepsHandler | JWT |
| GET | /api/v1/tasks/:id/timeline | getTaskTimelineHandler | JWT |
| GET | /api/v1/stats | getStatsHandler | JWT |
| GET | /api/v1/playbooks | listPlaybooksHandler | JWT |
| GET | /api/v1/skills | listSkillsHandler | JWT |
| GET | /api/v1/me | getMeHandler | JWT |
| GET | /api/v1/log-sources | listLogSourcesHandler | JWT |
| GET | /api/v1/siem-alerts | listSIEMalertsHandler | JWT |
| GET | /api/v1/notifications | getNotificationsHandler | JWT |

### Analyst + Admin

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| POST | /api/v1/tasks | createTaskHandler | JWT (analyst+) |
| POST | /api/v1/tasks/upload | uploadTaskHandler | JWT (analyst+) |
| POST | /api/v1/siem-alerts/:id/investigate | investigateAlertHandler | JWT (analyst+) |
| POST | /api/v1/investigations/:id/feedback | submitFeedbackHandler | JWT (analyst+) |

### Admin Only

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | /api/v1/feedback/stats | getFeedbackStatsHandler | JWT (admin) |
| GET | /api/v1/approvals/pending | getPendingApprovalsHandler | JWT (admin) |
| POST | /api/v1/approvals/:id/decide | decideApprovalHandler | JWT (admin) |
| POST | /api/v1/playbooks | createPlaybookHandler | JWT (admin) |
| PUT | /api/v1/playbooks/:id | updatePlaybookHandler | JWT (admin) |
| DELETE | /api/v1/playbooks/:id | deletePlaybookHandler | JWT (admin) |
| POST | /api/v1/log-sources | createLogSourceHandler | JWT (admin) |
| PUT | /api/v1/log-sources/:id | updateLogSourceHandler | JWT (admin) |
| DELETE | /api/v1/log-sources/:id | deleteLogSourceHandler | JWT (admin) |
| GET | /api/v1/tenants | listTenantsHandler | JWT (admin) |
| GET | /api/v1/tenants/:id | getTenantHandler | JWT (admin) |
| POST | /api/v1/tenants | createTenantHandler | JWT (admin) |
| PUT | /api/v1/tenants/:id | updateTenantHandler | JWT (admin) |
| GET | /api/v1/webhooks/endpoints | listWebhookEndpointsHandler | JWT |
| GET | /api/v1/webhooks/deliveries | listWebhookDeliveriesHandler | JWT |
| POST | /api/v1/webhooks/endpoints | createWebhookEndpointHandler | JWT (admin) |
| PUT | /api/v1/webhooks/endpoints/:id | updateWebhookEndpointHandler | JWT (admin) |
| DELETE | /api/v1/webhooks/endpoints/:id | deleteWebhookEndpointHandler | JWT (admin) |
| GET | /api/v1/models | listModelsHandler | JWT (admin) |
| POST | /api/v1/models | createModelHandler | JWT (admin) |
| PUT | /api/v1/models/:id | updateModelHandler | JWT (admin) |
| GET | /api/v1/models/ab-tests | listABTestsHandler | JWT (admin) |
| POST | /api/v1/models/ab-tests | createABTestHandler | JWT (admin) |
| POST | /api/v1/models/ab-tests/:id/complete | completeABTestHandler | JWT (admin) |

### Go API Source Files

| File | Purpose |
|------|---------|
| `api/main.go` | Router setup, middleware chain, route registration |
| `api/auth.go` | Register, Login handlers, JWT generation, bcrypt password hashing |
| `api/handlers.go` | Task CRUD, stats, notifications, timeline, audit |
| `api/feedback.go` | Investigation feedback submission + stats |
| `api/playbooks.go` | Playbook CRUD |
| `api/siem.go` | SIEM alert listing, investigation trigger |
| `api/tenants.go` | Tenant CRUD, webhook endpoint management |
| `api/temporal.go` | Temporal client, workflow submission |
| `api/models.go` | Model registry CRUD, A/B test management |
| `api/middleware.go` | CORS, logging, auth JWT validation, audit, RBAC (requireRole) |
| `api/security.go` | Rate limiting, account lockout, security headers |
| `api/db.go` | pgxpool connection setup |

### Middleware Chain

```
corsMiddleware -> securityHeadersMiddleware -> loggingMiddleware -> (authMiddleware -> auditMiddleware for protected routes)
```

### Key Request/Response Schemas

**Auth:**
- Register: `{email, password(min 6), display_name, tenant_id}` -> user object (201)
- Login: `{email, password}` -> `{token(JWT 24h), user}` (200)
- JWT Claims: `{tenant_id, user_id, email, role}` (HS256, lenient expiry for dev)
- Account lockout: 5 failed attempts -> locked 30 minutes

**Task Creation:**
- POST: `{task_type, input: {prompt, ...}}` -> `{task_id, workflow_id, status}` (202)
- Alert deduplication: SHA-256 fingerprint of (tenant_id, task_type, prompt, source_ip, dest_ip)
- If duplicate within dedup window: returns existing investigation_id + incremented count
- Playbook resolution: if input.playbook_id -> fetches steps + system_prompt_override

**File Upload:**
- POST multipart: file (.csv/.json/.txt/.log, max 10MB, read cap 50KB) + task_type + prompt
- Returns: `{task_id, workflow_id, filename, file_size}`

**SIEM Webhook:**
- POST raw JSON, auto-detects format (Splunk/Elastic/Generic)
- HMAC-SHA256 validation via X-Webhook-Signature header
- Normalizes: alert_name, severity, source_ip, dest_ip, rule_name
- Auto-investigation if configured: maps severity -> task_type (critical/high -> incident_response)

**Security Headers:**
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: strict-origin-when-cross-origin
- Cache-Control: no-store, no-cache, must-revalidate

**Rate Limiting:**
- Auth routes: 10 attempts per 15 minutes per IP (in-memory)
- Webhook delivery: 3 retries with exponential backoff (1s, 4s)
- Webhook timeout: 10 seconds

---

## 6. Python Worker

### Workflows (7)

| # | Workflow | Source | Description |
|---|---------|--------|-------------|
| 1 | ExecuteTaskWorkflow | `workflows.py` | Main investigation pipeline: memory enrichment -> code gen -> sandbox -> entity extraction -> guardrail -> approval -> report |
| 2 | DetectionWorkflow | `detection/workflow.py` | Pattern mining -> candidate generation -> Sigma rule creation -> validation |
| 3 | ResponseWorkflow | `response/workflow.py` | SOAR playbook execution: trigger evaluation -> action execution -> approval gates |
| 4 | CrossTenantWorkflow | `intelligence/cross_tenant_workflow.py` | Refresh cross-tenant materialized view |
| 5 | BootstrapWorkflow | `bootstrap/workflow.py` | Load MITRE/CISA data, generate synthetic investigations |
| 6 | FinetuningWorkflow | `finetuning/workflow.py` | Training data export -> quality scoring -> evaluation |
| 7 | SelfHealingWorkflow | `sre/workflow.py` | Scan failures -> diagnose -> patch -> test -> apply (dry-run default) |

### Activities (58)

**Core activities (activities.py -- 23 activities):**

| Activity | Purpose |
|----------|---------|
| `fetch_task` | Load task from agent_tasks table |
| `generate_code` | LLM code generation via LiteLLM with cached prompts |
| `validate_code` | AST prefilter + DryRunValidator (5s subprocess sandbox) |
| `execute_code` | Docker sandbox execution with seccomp + kill timer |
| `update_task_status` | Write task status to DB |
| `log_audit` | Write to audit_events table |
| `log_audit_event` | Alias for log_audit |
| `record_usage` | Log token usage to usage_records |
| `save_investigation_step` | Write to investigation_steps table |
| `check_followup_needed` | Parse JSON output for follow_up_needed flag |
| `generate_followup_code` | LLM code generation for followup steps |
| `check_requires_approval` | Approval gate logic (risk_level check) |
| `create_approval_request` | Create approval_requests record |
| `update_approval_request` | Update approval status |
| `retrieve_skill` | Load skill from agent_skills by ID |
| `write_investigation_memory` | Store to investigation_memory table |
| `fill_skill_parameters` | Extract params from prompt via LLM |
| `render_skill_template` | Jinja2 template rendering |
| `check_rate_limit_activity` | Lease-based rate limiting check (Redis) |
| `decrement_active_activity` | Release lease on completion |
| `heartbeat_lease_activity` | Extend lease TTL (call every 20s) |
| `validate_generated_code` | AST validation + syntax check |
| `enrich_alert_with_memory` | Two-pass memory enrichment (exact + pgvector semantic) |

**Entity graph activities (entity_graph.py -- 3 activities):**

| Activity | Purpose |
|----------|---------|
| `extract_entities` | LLM entity extraction with regex fallback |
| `write_entity_graph` | Normalize, hash, batch upsert entities + observations + edges |
| `embed_investigation` | Create investigations row with summary embedding |

**Detection activities (detection/ -- 4 activities):**

| Activity | Purpose |
|----------|---------|
| `mine_attack_patterns` | Mine entity/edge patterns from investigations |
| `generate_sigma_rule` | Generate Sigma rules via LLM (reasoning tier) |
| `validate_sigma_rule` | Validate rules against corpus (auto-approve if TP>=80%, FP<=10%) |
| `_list_candidates_for_generation` | Query candidates with status='candidate' |

**Response activities (response/ -- 6 activities):**

| Activity | Purpose |
|----------|---------|
| `load_playbook` | Load from response_playbooks table |
| `create_response_execution` | Insert response_executions record |
| `update_response_execution` | Update status + actions_executed |
| `execute_response_action` | Execute single action (7 types: BlockIP, DisableUser, IsolateEndpoint, RotateCredentials, CreateTicket, SendNotification, QuarantineFile) |
| `rollback_response_action` | Rollback completed action (reverse order) |
| `find_matching_playbooks` | Query playbooks matching verdict + risk_score threshold |

**Bootstrap activities (bootstrap/ -- 5 activities):**

| Activity | Purpose |
|----------|---------|
| `load_mitre_techniques` | Parse STIX JSON, batch upsert to mitre_techniques, batch embed |
| `load_cisa_kev` | Parse CISA JSON, insert to bootstrap_corpus |
| `generate_synthetic_investigation` | LLM generates investigation for MITRE technique |
| `process_bootstrap_entity` | Extract entities from generated investigation |
| `list_techniques` | Query mitre_techniques (paginated) |

**Finetuning activities (finetuning/ -- 5 activities):**

| Activity | Purpose |
|----------|---------|
| `export_finetuning_data` | Export investigations as JSONL training format |
| `score_training_quality` | Compute quality stats (avg/min/max/distribution) |
| `run_model_evaluation` | Run 5-scenario benchmark evaluation |
| `create_finetuning_job` | Insert finetuning_jobs record |
| `update_finetuning_job` | Update status + evaluation results |

**SRE activities (sre/ -- 5 activities):**

| Activity | Purpose |
|----------|---------|
| `scan_for_failures` | Scan Temporal for failed workflows + agent_tasks DB |
| `diagnose_failure` | Deterministic 4-category classifier + LLM fallback |
| `generate_patch` | Category-specific fix (rate limited: max 5/hour) |
| `test_patch` | Sandbox-isolated verification (syntax check + subprocess) |
| `apply_patch` | Safe application with backup + audit logging |

**Intelligence activities (intelligence/ -- 4 activities):**

| Activity | Purpose |
|----------|---------|
| `refresh_cross_tenant_intel` | Refresh materialized view, update tenant_count |
| `get_entity_intelligence` | Privacy-safe intelligence lookup |
| `compute_threat_score` | Score entity 0-100 (observations, multi-tenant, verdicts, recency) |
| `_list_multi_tenant_entities` | Query distinct entities in cross_tenant_intel |

**Reporting activities (reporting/ -- 1 activity):**

| Activity | Purpose |
|----------|---------|
| `generate_incident_report` | LLM-powered markdown + PDF report generation |

**Skills activities (skills/ -- 1 activity):**

| Activity | Purpose |
|----------|---------|
| `run_deobfuscation` | Sandbox deobfuscation (base64, hex, PowerShell, URL encoding) |

**FP Analysis activities (intelligence/ -- 1 activity):**

| Activity | Purpose |
|----------|---------|
| `analyze_false_positive` | Similarity search + LLM reasoning chain for FP confidence |

### Key Python Source Files

| File | Purpose |
|------|---------|
| `worker/main.py` | Worker startup, registers all workflows and activities |
| `worker/workflows.py` | ExecuteTaskWorkflow (main pipeline, 12 steps, retry logic) |
| `worker/activities.py` | Core activities (code gen, sandbox, entity extraction, guardrails) |
| `worker/model_config.py` | MODEL_TIERS dict (fast/standard/reasoning), ACTIVITY_TIER_MAP mapping activity -> tier, get_tier_config() |
| `worker/prompt_registry.py` | SHA256-based prompt versioning, register_prompt(), get_version() |
| `worker/llm_logger.py` | Fire-and-forget LLM call logging with per-model cost calculation |
| `worker/cost_calculator.py` | COST_PER_1K dict for 19 model entries, calculate_cost() |
| `worker/investigation_memory.py` | InvestigationMemory class, two-pass enrichment (exact DB match + pgvector semantic search) |
| `worker/investigation_cache.py` | SHA-256 indicator caching, check_cache(), store_cache(), 24h TTL |
| `worker/entity_graph.py` | Entity/edge/observation creation in DB |
| `worker/entity_normalize.py` | IOC normalization (IP, domain, hash, email, URL) |
| `worker/context_manager.py` | Model-aware head/tail truncation for context windows |
| `worker/prompt_init.py` | Registers 16 prompts at worker startup |
| `worker/rate_limiter.py` | Redis-based lease rate limiting |
| `worker/redis_client.py` | Redis connection helper |
| `worker/validation/dry_run.py` | DryRunValidator: static checks + 5s subprocess sandbox |
| `worker/prompts/investigation_prompt.py` | Investigation prompt template with memory injection |
| `worker/prompts/entity_extraction.py` | Entity extraction prompt |
| `worker/security/injection_detector.py` | Prompt injection detection |
| `worker/security/prompt_sanitizer.py` | Input sanitization |
| `worker/intelligence/blast_radius.py` | Blast radius analysis |
| `worker/intelligence/fp_analyzer.py` | False positive confidence scoring |
| `worker/intelligence/cross_tenant.py` | Cross-tenant entity resolution |
| `worker/reporting/incident_report.py` | Markdown + PDF report generation |
| `worker/skills/deobfuscation.py` | Code deobfuscation in sandbox |
| `worker/detection/pattern_miner.py` | Pattern mining from investigations |
| `worker/detection/sigma_generator.py` | Sigma rule generation via LLM |
| `worker/detection/rule_validator.py` | Rule validation against historical data |
| `worker/finetuning/data_export.py` | Training data export |
| `worker/finetuning/evaluator.py` | Model evaluation framework |
| `worker/models/registry.py` | Model registry + A/B testing + dynamic routing |
| `worker/sre/monitor.py` | Temporal failure scanner |
| `worker/sre/diagnose.py` | 4-category failure classifier + LLM fallback |
| `worker/sre/patcher.py` | Category-specific fix generation |
| `worker/sre/tester.py` | Sandbox-isolated patch verification |
| `worker/sre/applier.py` | Safe patch application with backup |

---

## 7. LLM Configuration

### Model Tiers (litellm_config.yaml)

| Tier | Primary | Fallback 1 | Fallback 2 | Air-Gap |
|------|---------|------------|------------|---------|
| hydra-fast | Groq Llama-3.1-8B | OpenRouter Gemini Flash 1.5 | - | Ollama qwen2.5:7b |
| hydra-standard | OpenRouter Gemini Pro 1.5 | Anthropic Claude Sonnet 4 | OpenAI GPT-4o-mini | Ollama qwen2.5:7b |
| hydra-reasoning | Anthropic Claude Sonnet 4 | OpenAI GPT-4o | hydra-standard | Ollama qwen2.5:7b |

**Backward compatibility aliases:**
- `"fast"` -> Groq Llama
- `"embed"` -> huggingface/BAAI/bge-base-en-v1.5

**Router settings:** allowed_fails=3, cooldown_time=60s, timeout=15s, retry_after=5s, routing_strategy=simple-shuffle, redis-backed

### Activity -> Tier Mapping (model_config.py)

| Tier | Activities |
|------|-----------|
| fast | extract_entities, check_guardrails, validate_generated_code, enrich_alert_with_memory |
| standard | generate_code, generate_incident_report, generate_sigma_rules, execute_playbook_action |
| reasoning | mine_patterns, validate_rules, diagnose_failure, generate_patch, score_quality |

---

## 8. MCP Server

Location: `mcp-server/`
Runtime: TypeScript + Node.js + @modelcontextprotocol/sdk

### Tools (7)

| Tool | Description |
|------|-------------|
| hydra_submit_alert | Submit security alert for investigation |
| hydra_get_report | Fetch investigation report by task_id/investigation_id |
| hydra_create_tenant | Onboard new customer (create tenant + admin user + JWT) |
| hydra_query | Read-only SQL against PostgreSQL (SELECT only, writes blocked) |
| hydra_health | Check all service health (API, worker, Postgres, Redis, LiteLLM, Temporal) |
| hydra_logs | Tail and filter Docker Compose logs |
| hydra_trigger_workflow | Start Temporal workflow (investigation, detection, self_healing, etc.) |

### Resources (7)

| URI | Description |
|-----|-------------|
| hydra://investigations/recent | Recent investigations |
| hydra://entities/top-threats | High-threat entities |
| hydra://detection/rules | Active detection rules |
| hydra://playbooks/active | Active response playbooks |
| hydra://health/summary | Service health summary |
| hydra://metrics/llm | LLM call statistics |
| hydra://feedback/accuracy | Feedback accuracy metrics |

### Prompts (6)

| Prompt | Parameters | Description |
|--------|------------|-------------|
| hydra-investigate-brute-force | source_ip, target_account, attempt_count | Submit brute force alert, wait 30s, fetch report |
| hydra-investigate-ransomware | hostname, indicators | Submit ransomware alert, retrieve report |
| hydra-investigate-c2 | beacon_ip, internal_host | Submit C2 beacon alert, retrieve report |
| hydra-daily-health-check | (none) | Full health check: services, self-healing, stats, risk entities |
| hydra-onboard-customer | company_name, admin_email | Create tenant + admin user, return JWT |
| hydra-generate-demo | (none) | Run 3 investigations (brute_force, c2, ransomware) in sequence |

### MCP Source Files

| File | Purpose |
|------|---------|
| `mcp-server/src/index.ts` | Tool/resource/prompt registration, MCP server startup |
| `mcp-server/src/api.ts` | HTTP client for Go API (JWT auth, task submission) |
| `mcp-server/src/db.ts` | Direct PostgreSQL queries (pg library) |
| `mcp-server/src/exec.ts` | Docker Compose command execution (logs, workflows) |

**Self-test:** `node index.ts --test` validates postgres, api, 7 tools, 7 resources, 6 prompts

---

## 9. Dashboard

**Stack:** React 19 + Vite 7 + Tailwind CSS 4 + TypeScript 5.9
**Port:** 3000 (nginx in production, Vite dev server in development)
**API proxy:** `/api` -> `localhost:8090`

### Pages (9)

| Route | Component | Description |
|-------|-----------|-------------|
| `/` and `/tasks` | TaskList | Main task listing |
| `/tasks/new` | NewTask | Create new investigation task |
| `/tasks/:id` | TaskDetail | Task detail with investigation waterfall |
| `/demo` | DemoPage | C2 beacon investigation demo |
| `/demo/:scenario` | DemoPage | Parameterized demo scenario |
| `/playbooks` | Playbooks | Playbook management |
| `/threat-intel` | ThreatIntel | Threat intelligence dashboard |
| `/log-sources` | LogSources | Log source configuration |
| `/settings` | Settings | Admin settings (admin only) |
| `/login` | Login | Authentication page |

### Components (12)

| Component | Description |
|-----------|-------------|
| InvestigationWaterfall | Vertical timeline with progress bar, status icons, DataFlowBadge |
| StepDetailPanel | Slide-out JSON viewer with copy, guardrail score, timestamps |
| GuardrailScoreBar | Score fill bar with threshold marker |
| ExecutiveSummary | 4 ROI metrics ribbon (alerts triaged, hours saved, MTTR, cost avoided) |
| DataFlowBadge | LOCAL/LLM badge per step |
| SovereigntyBanner | Data flow visualization + zero PII badge |
| DemoBanner | Amber demo mode indicator |
| DemoSelector | Demo launcher card with 7-step preview |
| Notifications | Real-time notification dropdown |
| Skeleton | Loading state placeholder |

### Hooks

| Hook | Description |
|------|-------------|
| useDemo | Timed step reveal for demo mode |

### Types

**WorkflowStep interface:**
- id, name, status, timing, input/output, guardrail, model, execution_context

**STEP_LABELS mapping:**
- 14 step names mapped to human-readable labels

### API Client (api/client.ts)

Functions: fetchTasks, fetchTaskDetail, fetchTaskSteps, fetchTaskTimeline, fetchPendingApprovals, decideApproval, createTask, uploadTask, fetchTaskAudit, fetchStats, fetchPlaybooks, fetchSkills, fetchSIEMAlerts, investigateAlert, fetchNotifications

**Auth:** JWT stored in localStorage, utilities: getUser(), clearToken()

---

## 10. Kubernetes Manifests

**Location:** `k8s/`
**Build system:** Kustomize

### Overlays (3)

| Overlay | Path | Purpose |
|---------|------|---------|
| dev | `k8s/overlays/dev/` | Development settings |
| production | `k8s/overlays/production/` | Production (KEDA scaling, resource limits) |
| airgap | `k8s/overlays/airgap/` | Air-gapped deployment |

### Base Manifests (20 files)

| File | Purpose |
|------|---------|
| namespace.yaml | Hydra namespace definition |
| secrets.yaml.example | Secret template |
| kustomization.yaml | Base kustomization config |
| api/deployment.yaml | API deployment |
| api/hpa.yaml | API horizontal pod autoscaler |
| api/service.yaml | API service |
| dashboard/ | Dashboard deployment + service |
| litellm/configmap.yaml | LiteLLM configuration |
| litellm/deployment.yaml | LiteLLM deployment |
| litellm/service.yaml | LiteLLM service |
| pgbouncer/ | PgBouncer deployment |
| postgres/configmap.yaml | PostgreSQL configuration |
| postgres/statefulset.yaml | PostgreSQL stateful set |
| postgres/service.yaml | PostgreSQL service |
| redis/ | Redis deployment |
| temporal/ | Temporal deployment |
| worker/deployment.yaml | Worker deployment |
| worker/hpa.yaml | Worker horizontal pod autoscaler |
| worker/keda-scaledobject.yaml | KEDA scale object |
| worker/networkpolicy.yaml | Worker network policy |

### Scaling Configuration

**Worker HPA:** min 2, max 50 replicas, target CPU 70%

**KEDA ScaledObject:** Temporal queue depth trigger -- scales workers based on pending workflow tasks

---

## 11. Migration History (001-019)

| # | File | Sprint | Purpose |
|---|------|--------|---------|
| 001 | sprint1g_entity_graph.sql | 1G | Entity graph: investigations (partitioned), entities, edges, observations, steps, memory, reports |
| 002 | schema_drift_fixes.sql | - | Fix mismatches between Go API / Python worker and init.sql |
| 003 | sprint1e_hardening.sql | 1E | Sandbox limits, sync commit, SCRAM-SHA-256, audit events |
| 004 | sprint1f_bootstrap.sql | 1F | Bootstrap corpus: MITRE ATT&CK + CISA KEV |
| 005 | sprint1l_golden_path.sql | 1L | Investigation reports, response integrations |
| 006 | sprint1k_cross_tenant.sql | 1K | Cross-tenant materialized view + privacy-safe public view |
| 007 | sprint1i_model_tiering.sql | 1I | LLM call log, prompt versioning |
| 008 | sprint2a_detection_engine.sql | 2A | Detection candidates + rules |
| 009 | sprint2b_soar_playbooks.sql | 2B | Response playbooks + executions |
| 010 | sprint3c_tenant_webhooks.sql | 3C | Webhook endpoints + deliveries, tenant max_concurrent |
| 011 | sprint3d_finetuning.sql | 3D | Finetuning jobs table |
| 012 | sprint3e_model_registry.sql | 3E | Model registry + A/B tests |
| 013 | sprint3f_security.sql | 3F | Data retention policies, audit enhancements |
| 014 | sprint4a_sre_agent.sql | 4A | Self-healing events + audit constraint update |
| 015 | sprint5_seed_skills.sql | 5 | Seed 5 core investigation skills, audit constraint update |
| 016 | alert_fingerprints.sql | 5 | Alert deduplication via SHA-256 fingerprints |
| 017 | investigation_feedback.sql | 7C | Analyst feedback + feedback_accuracy materialized view |
| 018 | cost_tracking.sql | 7D | cost_usd column + investigation_costs view |
| 019 | investigation_cache.sql | 7E | Investigation result cache (SHA-256 key, 24h TTL) |

### Applying Migrations

```bash
cat migrations/NNN_*.sql | docker exec -i hydra-postgres psql -U hydra -d hydra
```

---

## 12. Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| POSTGRES_PASSWORD | PostgreSQL password | hydra_dev_2026 |
| LITELLM_MASTER_KEY | LiteLLM API key | sk-hydra-dev-2026 |
| MINIO_ROOT_USER | MinIO access key | hydra |
| MINIO_ROOT_PASSWORD | MinIO secret key | hydra_dev_2026 |
| GROQ_API_KEY | Groq API key (fast tier) | - |
| OPENROUTER_API_KEY | OpenRouter key (standard tier) | - |
| ANTHROPIC_API_KEY | Anthropic key (reasoning tier) | - |
| OPENAI_API_KEY | OpenAI key (fallback) | - |
| JWT_SECRET | JWT signing secret | hydra-jwt-secret-dev-2026 |
| HYDRA_ENV | Environment name | development |
| HYDRA_LOG_LEVEL | Log level | info |
| HYDRA_LLM_MODEL | Force single model (leave unset for tiering) | (unset) |
| TEMPORAL_ADDRESS | Temporal server address | temporal:7233 |
| HYDRA_SIMILARITY_THRESHOLD | pgvector similarity threshold | 0 |

---

## 13. Live Data Summary

### Tenants and Users

- **4 tenants:** hydra-dev, acme-security, shield-mssp, acme
- **7 users:** admin + analysts across tenants
- **Dev login:** admin@hydra.local / hydra123 (role: admin, tenant: hydra-dev, UUID: e1c1bc5d-576f-4613-b6c3-99952b37b3ce)

### Entity Graph

- **304 entities** across 8 types: domain(77), file_hash(62), process(61), ip(35), device(30), user(22), url(14), email(3)
- **258 entity edges**
- **588 entity observations**

### Investigations

- **138 investigations:** 124 true_positive, 14 suspicious
- **10 agent tasks:** 5 completed, 4 failed, 1 pending

### Reference Data

- **691 MITRE ATT&CK techniques**
- **1,636 bootstrap corpus entries** (MITRE + CISA KEV + synthetic)
- **14 detection rules** (14 candidates)
- **5 response playbooks**
- **10 agent skills**

### LLM and Models

- **16 LLM call log entries**
- **2 registered models**

---

## 14. Development Conventions

### LLM Call Pattern

```python
from model_config import get_tier_config
from llm_logger import log_llm_call
from prompt_registry import get_version

config = get_tier_config("activity_name")  # Returns {model, temperature, max_tokens}
version = get_version("prompt_name")       # Returns SHA256[:12]
# ... make LiteLLM call ...
log_llm_call(
    activity_name="...",
    model_tier=config["tier"],
    model_id=config["model"],
    prompt_name="...",
    prompt_version=version,
    input_tokens=N,
    output_tokens=N,
    ...
)
```

### Temporal Workflow Imports

```python
with workflow.unsafe.imports_passed_through():
    from activities import generate_code, execute_code, ...
```

### Migration Application

```bash
cat migrations/NNN_*.sql | docker exec -i hydra-postgres psql -U hydra -d hydra
```

### New Activity Registration

1. Create function with `@activity.defn` decorator
2. Import in `worker/main.py`
3. Add to activities list in `main.py`
4. Add to `ACTIVITY_TIER_MAP` in `model_config.py` if it uses LLM

### Protected Files (never auto-patched by SRE)

- `sandbox/ast_prefilter.py`
- `sandbox/seccomp_profile.json`
- `sandbox/kill_timer.py`

### Line Endings

- `.gitattributes` enforces LF for `*.py`, `*.go`, `*.sql`, `*.yaml`, `*.json`, `*.md`
- `.editorconfig`: end_of_line = lf

### Linting

| Language | Tool | Configuration |
|----------|------|---------------|
| Python | flake8 | `--max-line-length=200 --ignore=E501,W503,E402` |
| Go | Built-in compiler | No separate linter configured |
| TypeScript | tsc -b | verbatimModuleSyntax (must use `import type` for type-only imports) |

### Database Access

```bash
# Interactive
docker exec -i hydra-postgres psql -U hydra -d hydra

# One-shot query
docker exec hydra-postgres psql -U hydra -d hydra -c "SQL"
```

### Worker Access

```bash
docker compose exec -T worker python -c "from module import X; ..."
```

### Runtime Notes

- **No Python/Go on Windows host** -- everything runs in Docker
- TypeScript/Node.js for dashboard and MCP server run locally
- All services communicate on `hydra-internal` bridge network
- Container naming convention: `hydra-{service}` (e.g., `hydra-postgres`, `hydra-api`)

---

## 15. Known Issues and Gaps

1. **No real SIEM integration** -- Webhook receiver exists but no actual SIEM connectors configured.
2. **No external enrichment** -- VirusTotal, AbuseIPDB etc. not integrated; LLM generates enrichment code.
3. **Investigation cache not wired into workflow** -- Table exists, module exists, but check_cache/store_cache not yet called from ExecuteTaskWorkflow.
4. **Accuracy validation requires LLM** -- 50 test alerts created but can only run with --dry-run without API keys.
5. **No HTTPS** -- All services run HTTP in development.
6. **Dashboard chunk size** -- Single 1MB JS bundle, needs code splitting for production.
7. **Partition tables** -- Only 2026 partitions exist; need partition creation for 2027+.
8. **No backup/restore** -- No automated database backup configured.
9. **Monitoring profiles** -- Prometheus/Grafana/exporters require `--profile monitoring` flag.
10. **Air-gap profile** -- Ollama requires `--profile airgap` and manual model pull via `scripts/airgap-setup.sh`.

---

## Appendix A: Scripts Reference

| Script | Purpose |
|--------|---------|
| `scripts/seed_demo.py` | Populate demo investigations and scenarios |
| `scripts/seed_skills.py` | Register reusable skills/playbooks in DB |
| `scripts/seed_templates.py` | Load prompt templates and investigation types |
| `scripts/seed_playbooks.py` | Create SOAR response playbooks |
| `scripts/recreate_seed_skills.py` | Reset and rebuild skill registry |
| `scripts/test_harness.py` | 20-test framework for core functionality |
| `scripts/test_integration.py` | 5 integration tests (E2E workflows) |
| `scripts/simulate_siem.py` | Generate synthetic SIEM alerts for testing |
| `scripts/load_test.py` | Performance testing (baseline, scaled, stress) |
| `scripts/airgap-setup.sh` | Configure air-gap/offline mode (pull Ollama models) |
| `scripts/test-airgap.sh` | Test air-gap deployment (4-step validation) |
| `scripts/export_airgap.sh` | Export models for air-gap environments |
| `scripts/pull_models.sh` | Download HuggingFace models locally |
| `scripts/autoscale.py` | KEDA/HPA autoscaling configuration |

## Appendix B: Accuracy Validation Framework

**Location:** `worker/tests/accuracy/`

**Files:**
- `test_alerts.json` -- 50 labeled alerts (25 TP, 25 FP, 10 categories x 5 alerts)
- `run_validation.py` -- Standalone runner (not pytest), supports --dry-run mode

**Categories:** c2_beacon, brute_force, phishing, lateral_movement, malware, data_exfiltration, privilege_escalation, reconnaissance, persistence, defense_evasion

**Metrics:** accuracy, precision, recall, F1, FPR, confusion matrix (TP/TN/FP/FN/UNK)

**Thresholds:** PROCEED (all >= 85%), IMPROVE (any 70-85%), KILL (any < 70%)

**Usage:**
```bash
docker compose exec -T worker python tests/accuracy/run_validation.py --dry-run
docker compose exec -T worker python tests/accuracy/run_validation.py  # live (requires LLM API keys)
```

## Appendix C: Sandbox Security Layers

**Layer 1: AST Prefilter** (`sandbox/ast_prefilter.py`)
- Forbidden modules: ctypes, multiprocessing, importlib, pty, fcntl, resource
- Forbidden functions: eval, exec, __import__
- Forbidden attributes: system, execl, execle, execlp, execlpe, execv, execve, execvp, execvpe, rmtree

**Layer 2: Seccomp Profile** (`sandbox/seccomp_profile.json`)
- Default action: SCMP_ACT_ERRNO (deny by default)
- Blocked: mount, kexec, perf_event, bpf, ptrace, unshare, reboot
- Allowed: 350+ standard syscalls for Python execution

**Layer 3: Kill Timer** (`sandbox/kill_timer.py`)
- Daemon thread, SIGKILL after 30 seconds
- Always cancel after execution completes

**Layer 4: Docker Isolation**
- `--network=none` (no network access)
- `--read-only` filesystem
- Resource limits from docker-compose.yml

## Appendix D: Cost Calculator Model Pricing

| Model | Input ($/1K) | Output ($/1K) |
|-------|-------------|---------------|
| groq/llama-3.1-8b-instant | 0.0002 | 0.0002 |
| openrouter/google/gemini-flash-1.5 | 0.0002 | 0.0002 |
| openrouter/google/gemini-pro-1.5 | 0.003 | 0.015 |
| anthropic/claude-sonnet-4-20250514 | 0.003 | 0.015 |
| openai/gpt-4o-mini | 0.0005 | 0.0015 |
| openai/gpt-4o | 0.005 | 0.015 |
| ollama/* (airgap) | 0.0 | 0.0 |
