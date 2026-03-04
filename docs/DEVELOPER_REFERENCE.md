# Developer Reference

This document provides technical internals for platform engineers, infrastructure developers, and API integrators working with Project Hydra.

## API Architecture (Golang / Gin)

The core gateway is written in Go using the `gin-gonic/gin` framework, chosen for extremely low overhead and high concurrency. 

All routing is centralized in `main.go`, dispatching to HTTP handlers in `handlers.go`.

### Key Systems
- **Authentication**: `middleware.go` handles JWT extraction, signature verification, and RBAC enforcement. Authorized contexts (`tenant_id`, `role`) are injected directly into the Gin context.
- **Relational Integrity**: Uses `pgxpool` for high-performance PostgreSQL connection multiplexing.

### Interacting with the API
Endpoints are prefixed with `/api/v1/`. For external integration, utilize a generated Bearer token to interface with the core logic. Ex:
`POST /api/v1/tasks` (Payload: JSON with `task_type` and `input`)

## The Temporal Worker Loop

Hydra handles long-running, non-deterministic AI tasks asynchronously using Temporal.io.

1. `createTaskHandler` (API) inserts a `pending` row in `agent_tasks` and asynchronously triggers `ExecuteTaskWorkflow` via the Temporal gRPC interface.
2. The Python Worker (`worker/workflows.py`) picks up the workflow, serving as the central orchestration loop.
3. The workflow executes specialized activities (`worker/activities.py`):
   - `plan_investigation`
   - `retrieve_skill` (Interfacing with the Hydra Intelligence Fabric)
   - `generate_investigation_code` / `render_skill_template`
   - `request_human_approval`
   - `execute_sandbox_code` (Interfacing with the Docker Engine API)

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
Ensure the Python template follows the parameter hydration logic defined in the Temporal Worker.

## Database Schema Map

The schema (`init.sql`) defines the multi-tenant architecture and memory systems:

### Transactional Engine
- `tenants`: Root organizational boundary.
- `users`: Identity and RBAC.
- `agent_tasks`: The parent ledger of all requested triage operations.
- `investigation_steps` / `agent_task_steps`: Granular execution logs mapped 1-to-M to tasks. Captures the specific phase (Plan, Exec, Approve) and token consumption.

### The Episodic Security Memory Engine
- `investigation_memory`: An append-only historical log leveraging `pgvector`. This tracks post-mortem investigation summaries mapped to 768-dimensional float arrays (`vector(768)`). When the Worker queries the DB, it performs cosine similarity matching to locate past incidents matching the current forensic fingerprint.
