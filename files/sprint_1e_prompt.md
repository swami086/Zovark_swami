# HYDRA Sprint 1E — Production Hardening
## Claude Code Prompt

---

You are building Sprint 1E for HYDRA, an AI-powered SOC investigation automation platform. This sprint hardens the platform for production deployment.

## Context

HYDRA receives SIEM alerts via webhook → Go API (port 8090) → Temporal workflows → Python workers → LLM generates analysis code → executes in sandboxed Docker → returns structured findings. The stack: Go API, Python workers, PostgreSQL 16 + pgvector, PgBouncer, Redis, Temporal, LiteLLM, Docker sandbox.

Previous sprints (1A-1D) built the core pipeline and scaling infrastructure. Sprint 1G added entity graph schema (investigations, entities, entity_edges, entity_observations tables). Sprint 1E hardens the foundation.

## Deliverables

### 1E-1: Docker Sandbox Hardening

Find where the sandbox Docker container is launched (likely in `worker/activities.py` or `worker/sandbox/`). Update the `docker run` command to add:

```
--memory=512m
--memory-swap=512m
--pids-limit=64
--cap-drop=ALL
--read-only
--tmpfs /tmp:size=64m,noexec,nosuid
```

Preserve existing flags: `--network=none`, seccomp profile, 30s kill timer.

**Verification:** Create a test that submits code designed to:
- Allocate excessive memory: `x = [0] * 10**9` — should be killed by OOM, not crash the host
- Fork bomb: `import os; [os.fork() for _ in range(1000)]` — should hit pids-limit
- Write to filesystem: `open('/etc/test', 'w')` — should fail on read-only filesystem
- Write to /tmp: `open('/tmp/test', 'w').write('ok')` — should succeed (tmpfs mounted)

### 1E-2: Synchronous Commit for Critical Writes

Find all database write operations in the worker codebase. For these specific operations, wrap the write in a transaction that sets synchronous_commit:

**Critical writes (synchronous_commit = on):**
- Investigation results (investigations table — Sprint 1G)
- Investigation steps (agent_task_steps table)
- Approval requests
- Audit log entries (if audit_events table exists, or agent_audit_log)
- Entity graph writes (entities, entity_edges, entity_observations)

**Leave async (synchronous_commit = off, current default):**
- usage_records
- working_memory_snapshots
- Redis counters

Implementation: Before the INSERT/UPDATE for critical writes, execute `SET LOCAL synchronous_commit = on;` within the same transaction.

**Verification:** 
- Run `SHOW synchronous_commit;` — should show `off` (global default unchanged)
- Submit an investigation, then immediately `pg_ctl stop -m immediate` the postgres container
- Restart postgres, verify investigation data survived

### 1E-3: Auth Hardening — MD5 to SCRAM-SHA-256

**Step 1:** Update PostgreSQL config to use SCRAM:
- Find postgresql.conf (likely in docker volume or init config) and set `password_encryption = scram-sha-256`
- Or add to init.sql: `ALTER SYSTEM SET password_encryption = 'scram-sha-256';`

**Step 2:** Regenerate password hashes:
```sql
ALTER USER hydra PASSWORD 'hydra';  -- or whatever the current password is
```
(This re-hashes with SCRAM since we changed password_encryption)

**Step 3:** Update PgBouncer config:
- Find pgbouncer.ini or equivalent config
- Change `auth_type = md5` to `auth_type = scram-sha-256`
- Update userlist.txt if it contains md5 hashes

**Step 4:** Update pg_hba.conf:
- Change `md5` to `scram-sha-256` for all entries

**Verification:** 
- `docker compose down -v; docker compose up -d`
- Worker connects successfully through PgBouncer
- `SELECT rolname, rolpassword LIKE 'SCRAM%' as is_scram FROM pg_authid WHERE rolname = 'hydra';` returns true

### 1E-4: Audit Log Table

Create an append-only audit_events table (if not already covered by agent_audit_log):

```sql
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'investigation_started', 'investigation_completed', 'code_executed',
        'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
        'entity_extracted', 'detection_generated', 'user_login', 'user_registered'
    )),
    actor_id UUID,
    actor_type VARCHAR(20) CHECK (actor_type IN ('user', 'worker', 'system')),
    resource_type VARCHAR(50),
    resource_id UUID,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);
```

- Create monthly partitions (same pattern as investigations)
- Grant INSERT-only privileges: `REVOKE UPDATE, DELETE ON audit_events FROM hydra;`
  - Note: this only works if you have a separate app role. If hydra is the owner, you'll need a separate `hydra_app` role with restricted permissions. Document the approach.
- Wire audit inserts into the Temporal workflow at each critical step (investigation start, completion, code execution, entity extraction)

### 1E-5: FK Constraints Restoration

Check if agent_tasks has FK constraints to tenants and users. PostgreSQL 16 supports FKs from partitioned tables. If FKs were dropped for partitioning:

```sql
ALTER TABLE agent_tasks ADD CONSTRAINT fk_tasks_tenant 
    FOREIGN KEY (tenant_id) REFERENCES tenants(id);
```

Test with existing data to verify no orphaned rows. Measure write latency impact with a quick benchmark (10 concurrent inserts before/after).

## Important Constraints

- All changes must preserve existing pipeline functionality
- Docker Compose and Kubernetes manifests both need updating where relevant
- Air-gap compatibility must be maintained
- PgBouncer must continue working after auth changes
- No Python on Windows host — test inside Docker containers

## Definition of Done

- [ ] Memory bomb and fork bomb fail gracefully in sandbox
- [ ] Critical writes survive `docker compose stop postgres` (immediate kill)
- [ ] PgBouncer connects via SCRAM-SHA-256
- [ ] Audit trail exists for a full investigation lifecycle
- [ ] FK constraints enforced on partitioned tables (or documented why not)
- [ ] All existing tests still pass
- [ ] Git commit: "Sprint 1E: Production hardening — sandbox, sync commit, SCRAM, audit, FKs"
