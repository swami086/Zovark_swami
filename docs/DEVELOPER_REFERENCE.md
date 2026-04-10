# Developer Reference

**Version: v1.5.1 | Date: 2026-03-24**

This document provides technical internals for platform engineers, infrastructure developers, and API integrators working with Project Zovark.

## API Architecture (Golang / Gin)

The core gateway is written in Go using the `gin-gonic/gin` framework, chosen for extremely low overhead and high concurrency.

All routing is centralized in `main.go`, dispatching to HTTP handlers across 27 `.go` files covering auth, RBAC, SIEM ingestion, Temporal orchestration, playbooks, shadow mode, kill switch, token quotas, NATS publishing, and OIDC SSO.

### Key Systems

- **Authentication & Authorization**: `middleware.go` handles JWT extraction, signature verification (HMAC only — other signing methods are rejected), and RBAC enforcement. Authorized contexts (`tenant_id`, `role`) are injected directly into the Gin context.
  - **Access tokens** expire in **15 minutes** (previously 24 hours). The expired-token bypass has been removed.
  - **Refresh tokens** (7-day lifetime) are issued in **httpOnly** cookies with `SameSite=Strict`.
  - `POST /api/v1/auth/refresh` — issues a new access token from the refresh cookie. No request body required; the server reads the cookie automatically.
  - `POST /api/v1/auth/logout` — clears the refresh cookie and invalidates the session.
  - **JWT_SECRET must be >= 32 characters.** The server will fatal-exit on startup if this requirement is not met. Do not use short or default secrets.
  - Signing method validation enforces **HMAC only** — tokens signed with RSA, ECDSA, or other algorithms are rejected outright.

- **OIDC Integration** (`api/oidc.go`):
  - ID tokens are verified against the provider's **JWKS** endpoint (RSA signatures).
  - Issuer and audience claims are validated on every token.
  - JWKS keys are cached and **auto-refreshed** on key rotation.
  - **JIT (Just-In-Time) user provisioning**: users are created on first OIDC login if they do not already exist.
  - **Claims mapping**: OIDC claims are mapped to Zovark roles and tenant assignments.

- **Relational Integrity**: Uses `pgxpool` for high-performance PostgreSQL connection multiplexing.

### Interacting with the API
Endpoints are prefixed with `/api/v1/`. For external integration, utilize a generated Bearer token to interface with the core logic. Ex:
`POST /api/v1/tasks` (Payload: JSON with `task_type` and `input`)

## The Temporal Worker Loop

Zovark handles long-running, non-deterministic AI tasks asynchronously using Temporal.io.

The Python worker (`worker/`) currently implements **10 workflows** and **95 activities**, spanning investigation orchestration, detection engineering, SOAR response, shadow mode validation, and more.

1. `createTaskHandler` (API) inserts a `pending` row in `agent_tasks` and asynchronously starts Temporal workflow **`InvestigationWorkflowV2`** (override with `ZOVARK_WORKFLOW_VERSION` if needed).
2. The Python worker (`worker/main.py`) registers `InvestigationWorkflowV2` from `worker/stages/register.py` and runs the V2/V3 stage activities (`ingest_alert`, `analyze_alert`, `execute_investigation`, `assess_results`, `apply_governance`, `store_investigation`).
3. Legacy and auxiliary activities remain in `worker/_legacy_activities.py` (re-exported via `worker/activities/__init__.py`); the V2 investigation stages live under `worker/stages/`. References to a monolithic `ExecuteTaskWorkflow` or single `workflows.py` entrypoint are obsolete—the canonical investigation workflow is **`InvestigationWorkflowV2`**, registered from `worker/stages/register.py` in `worker/main.py`.

### Key Worker Modules

| Module | Purpose |
|--------|---------|
| `worker/shadow.py` | Shadow mode workflow and 5 activities — safety-first automation where actions are proposed but not executed until validated |
| `worker/pii_detector.py` | PII detection (9 regex patterns) and masking for logs and outputs |
| `worker/stampede.py` | Anti-stampede protection — request coalescing, probabilistic cache refresh, shard locks |
| `worker/token_quota.py` | Per-tenant token quota enforcement with circuit breaker |
| `worker/nats_consumer.py` | NATS JetStream consumer (raw TCP) for high-throughput alert ingestion |

## Augmenting the Intelligence Fabric

Developers can inject proprietary methodologies directly into the Intelligence Fabric database table (`agent_skills`).

To add an Executable skill, insert a row heavily utilizing the `code_template` schema:
```sql
INSERT INTO agent_skills (skill_name, skill_slug, threat_types, investigation_methodology, code_template, example_prompt)
VALUES (
    'Memory Dump Analysis',
    'memory_dump_analysis',
    '{"Memory Corruption","Rootkits"}',
    'Analyze raw hex dumps for known magic byte signatures.',
    'import sys\n# {PARAMETERS_HERE}\nprint("Executed")',
    'Scan the provided memory dump for MZ headers'
);
```
Ensure the Python template follows the parameter zovarktion logic defined in the Temporal Worker.

## Database Schema Map

The schema (`init.sql`) defines the multi-tenant architecture and memory systems:

### Transactional Engine
- `tenants`: Root organizational boundary.
- `users`: Identity and RBAC.
- `agent_tasks`: The parent ledger of all requested triage operations.
- `investigation_steps` / `agent_task_steps`: Granular execution logs mapped 1-to-M to tasks. Captures the specific phase (Plan, Exec, Approve) and token consumption.

### The Episodic Security Memory Engine
- `investigation_memory`: An append-only historical log leveraging `pgvector`. This tracks post-mortem investigation summaries mapped to 768-dimensional float arrays (`vector(768)`). When the Worker queries the DB, it performs cosine similarity matching to locate past incidents matching the current forensic fingerprint.
