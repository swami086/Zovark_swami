# HYDRA Block 1: Horizontal Scaling — Complete Session Prompts
## 6 Sessions | Paste each into a FRESH Claude Code chat
## Each session has: shared context + session-specific task

---

# ═══════════════════════════════════════════════
# SHARED CONTEXT — Paste this at the TOP of EVERY session
# ═══════════════════════════════════════════════

```
I'm building HYDRA — an autonomous security investigation AI agent. Here's the full context:

=== PRODUCT ===
HYDRA receives security alerts/logs, matches them to investigation skills, executes battle-tested Python detection templates in a sandboxed environment, and produces structured findings (risk scores, IOCs, recommendations, MITRE mappings). It runs air-gapped with local LLM inference.

=== ARCHITECTURE ===
- 8 Docker containers: postgres (pgvector), api (Go/Gin on port 8090), worker (Python/Temporal), temporal, litellm, redis, embedding, dashboard (React on port 3000)
- Worker executes Temporal workflows: fetch_task → retrieve_skill → render_template → sandbox_execute → save_results
- Skills table: agent_skills (skill_slug, code_template, parameters, threat_types, mitre_tactics, mitre_techniques)
- Tasks table: agent_tasks (id, input, output, status, skill_id, execution_ms, tokens_used, severity)
- 5-layer sandbox: AST prefilter → seccomp → no-network → memory limits → kill timer

=== CURRENT STATUS (Sprint 12 COMPLETE) ===
- 10 executable skill templates in DB (brute-force, ransomware, lateral-movement, c2, phishing + 5 more)
- Test harness: 20/20 passing (5 skills × 4 difficulty levels: clean, easy, hard, multi_attack)
- Integration test: 5/5 passing (full API → Temporal → Worker → Sandbox → DB pipeline)
- Zero false positives on clean data
- Risk scores: brute_force=90, ransomware=60, lateral_movement=90, c2=60, phishing=70

=== GIT STATUS ===
- Repo: C:\Users\vinay\Desktop\HYDRA\hydra-mvp
- Branch: master
- Last commit: 9d7c691 "Sprint 12: 20/20 harness + 5/5 integration - test framework complete"
- Clean working tree

=== FILES THAT MATTER ===
- worker/main.py (Temporal worker entrypoint)
- worker/activities.py (18 Temporal activities including retrieve_skill, render_skill_template, execute_code)
- worker/workflows.py (ExecuteTaskWorkflow orchestration)
- api/handlers.go (REST endpoints)
- api/middleware.go (JWT auth)
- docker-compose.yml (all services)
- scripts/test_harness.py (benchmark runner)
- scripts/test_integration.py (pipeline test)

=== ENVIRONMENT ===
- Windows 11, PowerShell (use semicolons not &&, no piping to head/tail on host)
- Docker Desktop
- Container names: hydra-postgres, hydra-api, hydra-worker, hydra-temporal, hydra-litellm, hydra-redis, hydra-embedding, hydra-dashboard
- DB: user=hydra, database=hydra, password=hydra_dev_2026, host=postgres (inside containers) or localhost (from host)
- API: port 8090 (hydra-api inside containers, localhost:8090 from host)
- To run integration tests: docker exec -e HYDRA_API_URL=http://hydra-api:8090/api/v1 -e DATABASE_URL=postgresql://hydra:hydra_dev_2026@postgres:5432/hydra hydra-worker python /app/scripts/test_integration.py
- To run harness: docker exec hydra-worker python /app/scripts/test_harness.py
- When rebuilding worker: docker compose up -d --build worker, then re-copy test files: docker cp tests hydra-worker:/app/tests

=== CRITICAL RULES ===
1. NEVER rewrite files from scratch — surgical edits only
2. NEVER drop/recreate tables — use ALTER TABLE ADD COLUMN (exception: partitioning migration in session 1.3 requires controlled rename+recreate with data migration)
3. Always test after each change
4. Inside containers use Linux commands, on host use PowerShell
5. Skills table is "agent_skills" with column "code_template" (NOT "skills" or "template_code")
6. Commit after every significant milestone
```

---

# ═══════════════════════════════════════════════
# SESSION 1.1 — Stateless Worker + Worker Identity
# ═══════════════════════════════════════════════

**Paste the shared context above, then paste this:**

```
=== BLOCK 1 CONTEXT ===
We're implementing horizontal scaling so Hydra can handle 500+ concurrent investigations. This is Session 1 of 6. Each session builds on the previous.

=== IMMEDIATE TASK: Make worker stateless + add worker identity ===

DO THIS IN ORDER:

STEP 1 — Audit for in-memory state:
- Read worker/main.py, worker/activities.py, and worker/workflows.py completely
- Identify any module-level variables, caches, dicts, counters, or singletons that store state between task executions
- List every piece of in-memory state you find
- For each one, decide: move to Redis, move to Postgres, or make it stateless (re-fetch each time)
- Apply the fixes. If something is a config value that doesn't change, it can stay. If it accumulates data across tasks, it must move.

STEP 2 — Add worker identity:
- Generate a unique worker_id at worker startup in main.py: use format "{hostname}-{pid}-{random4chars}"
- Store it as a module-level constant (this is identity, not mutable state)
- Log the worker_id at startup: "Worker {worker_id} starting on task queue hydra-investigations"
- Also read WORKER_ID from environment variable if present (K8s will set this to pod name later), fall back to the generated format
- Pass worker_id through the Temporal workflow context so activities can access it

STEP 3 — Record worker_id in database:
- ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS worker_id VARCHAR(100);
- In the activity that saves task results (check activities.py for the save/complete function), write worker_id to agent_tasks
- Do NOT modify any other tables

STEP 4 — Verify:
- Rebuild worker: docker compose up -d --build worker
- Re-copy tests: docker cp tests hydra-worker:/app/tests
- Run integration test (5/5 must still pass)
- Query DB to verify worker_id is populated:
  docker exec hydra-postgres psql -U hydra -d hydra -c "SELECT id, task_type, worker_id, status FROM agent_tasks ORDER BY created_at DESC LIMIT 5;"
- Run harness (20/20 must still pass)

STEP 5 — Commit:
git add -A && git commit -m "Block 1.1: Stateless worker + worker identity tracking"

=== RULES FOR THIS SESSION ===
- ONLY modify: worker/main.py, worker/activities.py, worker/workflows.py
- DO NOT touch docker-compose.yml (no scaling yet)
- DO NOT add Redis connections (that's session 1.3)
- DO NOT add PgBouncer (that's session 1.3)
- DO NOT create load test scripts (that's session 1.4)
- DO NOT touch the API, dashboard, or skill templates
- If you find state that should move to Redis, just add a TODO comment for now and make it stateless by re-fetching

STOP after commit and report: what in-memory state did you find, what did you fix, and are all tests green?
```

---

# ═══════════════════════════════════════════════
# SESSION 1.2 — Multi-Worker Scaling
# ═══════════════════════════════════════════════

**Prerequisite: Session 1.1 committed, all tests green.**

**Paste the shared context, then paste this:**

```
=== BLOCK 1 CONTEXT ===
Session 1.1 is complete. Worker is stateless with worker_id tracking. Now we enable multi-worker scaling.

=== PRE-FLIGHT CHECK ===
Before making any changes, verify the baseline:
1. docker exec hydra-worker python /app/scripts/test_harness.py → must be 20/20
2. docker exec hydra-postgres psql -U hydra -d hydra -c "SELECT worker_id FROM agent_tasks WHERE worker_id IS NOT NULL LIMIT 1;" → must return a row

If either fails, STOP and report. Do not proceed.

=== IMMEDIATE TASK: Enable docker compose --scale worker=N ===

DO THIS IN ORDER:

STEP 1 — Fix docker-compose.yml for worker scaling:
- Check if the worker service has any "ports:" mapping. If yes, REMOVE it (workers don't serve HTTP)
- Check if the worker service has "container_name: hydra-worker". If yes, REMOVE it (container_name prevents scaling because names must be unique)
- Ensure the worker service has:
  - depends_on with health checks for postgres and temporal
  - restart: unless-stopped
  - The same PYTHONUNBUFFERED=1 environment variable
  - The same task queue name in its config/env (all workers must listen on the same queue)
- Ensure the worker's Temporal connection uses the service name "temporal" not a hardcoded IP
- Add a healthcheck to the worker service if it doesn't have one:
  healthcheck:
    test: ["CMD", "python", "-c", "import temporalio; print('ok')"]
    interval: 30s
    timeout: 10s
    retries: 3

STEP 2 — Verify single worker still works:
- docker compose up -d --build worker
- Find the new container name using: docker ps --filter "ancestor=hydra-mvp-worker" --format "{{.Names}}"
  (it will be something like hydra-mvp-worker-1 instead of hydra-worker)
- Copy tests to the new container name: docker cp tests <new-container-name>:/app/tests
- Run integration test → 5/5
- Run harness → 20/20

STEP 3 — Update all scripts and commands that reference "hydra-worker" by hardcoded name:
- Search the entire codebase for "hydra-worker" string references
- Update test scripts if they reference container names
- Document the new naming convention: hydra-mvp-worker-1, hydra-mvp-worker-2, etc.

STEP 4 — Scale to 4 workers:
- docker compose up -d --scale worker=4
- Verify all 4 are running: docker ps --filter "name=worker" --format "{{.Names}} {{.Status}}"
- All 4 should show "Up" with healthy status
- Check Temporal UI or logs to verify all 4 workers registered on the same task queue

STEP 5 — Test task distribution:
- Submit 5 investigations rapidly via integration test
- After completion, check which worker handled each:
  docker exec hydra-mvp-postgres-1 psql -U hydra -d hydra -c "SELECT task_type, worker_id, status FROM agent_tasks ORDER BY created_at DESC LIMIT 10;"
  (NOTE: postgres container name may have changed too — find it with docker ps)
- At least 2 different worker_ids should appear (proving distribution)
- If all tasks went to the same worker, that's OK for 5 tasks — Temporal's task queue is pull-based and may not distribute evenly with low volume

STEP 6 — Test worker resilience:
- With 4 workers running, kill one: docker stop hydra-mvp-worker-2
- Submit an investigation via API
- It should succeed (handled by one of the remaining 3 workers)
- Restart the stopped worker: docker start hydra-mvp-worker-2
- Verify it rejoins and picks up tasks

STEP 7 — Scale back to 1 for clean state:
- docker compose up -d --scale worker=1
- Verify 20/20 harness still passes with single worker

STEP 8 — Commit:
git add -A && git commit -m "Block 1.2: Multi-worker scaling — docker compose --scale worker=N"

=== RULES FOR THIS SESSION ===
- ONLY modify: docker-compose.yml, and ONLY the worker service definition
- You MAY need to update test scripts if they reference "hydra-worker" by hardcoded name
- DO NOT add PgBouncer or Redis config yet
- DO NOT create load test scripts yet
- DO NOT modify worker Python code (that was session 1.1)
- DO NOT modify the API or dashboard

STOP after commit and report: how many workers ran, did tasks distribute, did resilience test pass?
```

---

# ═══════════════════════════════════════════════
# SESSION 1.3 — PgBouncer + Postgres Tuning + Redis + Partitioning
# ═══════════════════════════════════════════════

**Prerequisite: Session 1.2 committed, scaling to 4 workers verified.**

**Paste the shared context, then paste this:**

```
=== BLOCK 1 CONTEXT ===
Sessions 1.1 and 1.2 complete. Worker is stateless, worker_id tracked, multi-worker scaling works with docker compose --scale worker=N.

Problem: With 4+ workers, each opens its own Postgres connections. Postgres default max_connections=100. At 10+ workers plus API plus Temporal, we hit the wall. We also need Redis for shared state and table partitioning for long-term scale.

=== PRE-FLIGHT CHECK ===
1. docker compose up -d --scale worker=1
2. docker ps → all services healthy
3. Run integration test → 5/5

=== IMMEDIATE TASK: Postgres hardening + PgBouncer + Redis + Partitioning ===

DO THIS IN ORDER:

STEP 1 — Harden Postgres configuration:

1a. Create config/postgresql.conf with these settings:

    # Connection limits — budgeted, not default
    max_connections = 200
    # Budget: PgBouncer=50, API=25, Temporal=15, Embedding=5, Admin=5, Reserve=20 = 120 used, 80 headroom

    # Memory — tuned for 4GB RAM (adjust for actual deployment)
    shared_buffers = 1GB
    effective_cache_size = 3GB
    work_mem = 16MB
    maintenance_work_mem = 256MB

    # WAL — tuned for write-heavy workload
    wal_buffers = 64MB
    max_wal_size = 2GB
    min_wal_size = 1GB
    checkpoint_completion_target = 0.9
    checkpoint_timeout = 10min

    # Write performance — trade durability for speed (Temporal retries on crash)
    synchronous_commit = off
    commit_delay = 100
    commit_siblings = 5

    # Replication — enabled even for single instance (ready for future read replica)
    wal_level = replica
    max_wal_senders = 5
    max_replication_slots = 5
    hot_standby = on

    # Connection handling
    tcp_keepalives_idle = 600
    tcp_keepalives_interval = 30
    tcp_keepalives_count = 3

    # Logging
    log_min_duration_statement = 500
    log_connections = off
    log_disconnections = off
    log_lock_waits = on
    log_statement = 'none'
    log_line_prefix = '%t [%p] %u@%d '

    # Autovacuum — aggressive for write-heavy tables
    autovacuum_vacuum_scale_factor = 0.05
    autovacuum_analyze_scale_factor = 0.02
    autovacuum_vacuum_cost_delay = 2
    autovacuum_max_workers = 4

1b. Mount this config in docker-compose.yml postgres service:
    volumes:
      - ./config/postgresql.conf:/etc/postgresql/postgresql.conf
      - postgres_data:/var/lib/postgresql/data
    command: postgres -c config_file=/etc/postgresql/postgresql.conf

1c. Restart postgres and verify:
    docker compose up -d postgres
    docker exec <postgres-container> psql -U hydra -d hydra -c "SHOW max_connections;"
    → Should return 200
    docker exec <postgres-container> psql -U hydra -d hydra -c "SHOW shared_buffers;"
    → Should return 1GB
    docker exec <postgres-container> psql -U hydra -d hydra -c "SHOW wal_level;"
    → Should return replica
    docker exec <postgres-container> psql -U hydra -d hydra -c "SHOW synchronous_commit;"
    → Should return off

STEP 2 — Add PgBouncer to docker-compose.yml:

2a. Add a new service "pgbouncer":
    pgbouncer:
      image: edoburu/pgbouncer:latest
      environment:
        DATABASE_URL: postgres://hydra:hydra_dev_2026@postgres:5432/hydra
        POOL_MODE: transaction
        MAX_CLIENT_CONN: 400
        DEFAULT_POOL_SIZE: 25
        MIN_POOL_SIZE: 5
        RESERVE_POOL_SIZE: 20
        RESERVE_POOL_TIMEOUT: 3
        MAX_DB_CONNECTIONS: 50
        SERVER_IDLE_TIMEOUT: 300
        QUERY_TIMEOUT: 30
      depends_on:
        postgres:
          condition: service_healthy
      healthcheck:
        test: ["CMD", "pg_isready", "-h", "localhost", "-p", "6432"]
        interval: 10s
        timeout: 5s
        retries: 3

2b. Change the worker service's DATABASE_URL to point to pgbouncer:6432 instead of postgres:5432
    - Find the env var in docker-compose.yml for the worker (might be DATABASE_URL or POSTGRES_HOST or similar)
    - Change host from postgres to pgbouncer, port from 5432 to 6432
    - Leave the API service pointing directly at postgres:5432 (Go has its own connection pooling)

2c. IMPORTANT: Check if worker/activities.py uses prepared statements:
    - Search for cursor.prepare(), %s paramstyle is fine
    - psycopg2 with %s parameters works with transaction-mode PgBouncer
    - If there ARE prepared statements (named cursors, server-side cursors), switch POOL_MODE to session
    - Add a comment in docker-compose.yml explaining the pool mode choice

2d. Verify PgBouncer works:
    docker compose up -d
    Run integration test → 5/5 (queries now go through PgBouncer)
    Run harness → 20/20
    Check connections:
    docker exec <pgbouncer-container> psql -p 6432 -U hydra pgbouncer -c "SHOW POOLS;"

STEP 3 — Configure Redis for shared state:

3a. Redis container should already exist in docker-compose.yml (hydra-redis). Verify it's running.
    If it doesn't exist, add it:
    redis:
      image: redis:7-alpine
      healthcheck:
        test: ["CMD", "redis-cli", "ping"]
        interval: 10s
        timeout: 5s
        retries: 3

3b. Add REDIS_URL=redis://redis:6379/0 to worker environment in docker-compose.yml

3c. Create worker/redis_client.py:
    - Lazy Redis connection (connect on first use, reuse thereafter)
    - This is a per-process singleton — each worker process gets its own Redis connection. This is fine because Redis connections are lightweight and this is connection identity, not shared state.
    - Implement these functions:
      get_active_count(tenant_id: str) -> int
      increment_active(tenant_id: str) -> int
      decrement_active(tenant_id: str) -> int
      check_rate_limit(tenant_id: str, max_concurrent: int) -> bool
        # Uses Redis INCR atomically — if value after INCR > max, DECR and return False
        # Key pattern: "hydra:active:{tenant_id}" with TTL of 1 hour (safety net for crashes)

3d. Add rate limit check to the workflow:
    - In worker/workflows.py, BEFORE starting an investigation:
      - Read tenant's max_concurrent from DB (or default 10)
      - Call check_rate_limit(tenant_id, max_concurrent)
      - If over limit, fail the task with status "rate_limited" and message "Tenant has {active}/{max} concurrent investigations"
    - On investigation complete (success or failure), call decrement_active(tenant_id)
    - Wrap decrement in try/finally so it always runs even on failure

3e. Add tenant config columns if they don't exist:
    Check if tenants table exists first. If it does:
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_concurrent_investigations INT DEFAULT 10;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_daily_tokens BIGINT DEFAULT 1000000;
    If tenants table doesn't exist, skip this — use hardcoded default of 10.

STEP 4 — Table partitioning for agent_tasks:

4a. FIRST check the current state of agent_tasks:
    docker exec <postgres-container> psql -U hydra -d hydra -c "SELECT count(*) FROM agent_tasks;"
    docker exec <postgres-container> psql -U hydra -d hydra -c "\d agent_tasks"
    docker exec <postgres-container> psql -U hydra -d hydra -c "SELECT conname, conrelid::regclass FROM pg_constraint WHERE confrelid = 'agent_tasks'::regclass;"
    (Check for foreign keys pointing TO agent_tasks — these block partitioning)

4b. If the table has fewer than 10,000 rows (it should — we're in dev), do the migration:
    
    -- Rename existing table
    ALTER TABLE agent_tasks RENAME TO agent_tasks_old;
    
    -- Create partitioned table with same schema
    CREATE TABLE agent_tasks (LIKE agent_tasks_old INCLUDING ALL) PARTITION BY RANGE (created_at);
    
    -- Create monthly partitions
    CREATE TABLE agent_tasks_2026_03 PARTITION OF agent_tasks FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
    CREATE TABLE agent_tasks_2026_04 PARTITION OF agent_tasks FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
    CREATE TABLE agent_tasks_2026_05 PARTITION OF agent_tasks FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
    CREATE TABLE agent_tasks_2026_06 PARTITION OF agent_tasks FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
    
    -- Migrate data
    INSERT INTO agent_tasks SELECT * FROM agent_tasks_old;
    
    -- Verify counts match
    -- Then drop old table
    DROP TABLE agent_tasks_old;

    IF there are foreign keys pointing TO agent_tasks:
    - Drop those foreign key constraints before the migration
    - Document which constraints were dropped
    - Add a comment: "FK constraints removed for partitioning — enforce at application level"

4c. Create auto-partition function:
    CREATE OR REPLACE FUNCTION create_monthly_partition() RETURNS void AS $$
    DECLARE
        next_month DATE := date_trunc('month', now() + interval '1 month');
        partition_name TEXT;
        start_date TEXT;
        end_date TEXT;
    BEGIN
        partition_name := 'agent_tasks_' || to_char(next_month, 'YYYY_MM');
        start_date := to_char(next_month, 'YYYY-MM-DD');
        end_date := to_char(next_month + interval '1 month', 'YYYY-MM-DD');
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = partition_name) THEN
            EXECUTE format('CREATE TABLE %I PARTITION OF agent_tasks FOR VALUES FROM (%L) TO (%L)', partition_name, start_date, end_date);
            RAISE NOTICE 'Created partition: %', partition_name;
        END IF;
    END;
    $$ LANGUAGE plpgsql;

    -- Run it once to verify
    SELECT create_monthly_partition();

4d. Add performance indexes:
    CREATE INDEX CONCURRENTLY idx_tasks_tenant_status ON agent_tasks(tenant_id, status);
    CREATE INDEX CONCURRENTLY idx_tasks_skill_created ON agent_tasks(skill_id, created_at DESC);
    CREATE INDEX CONCURRENTLY idx_tasks_worker ON agent_tasks(worker_id) WHERE worker_id IS NOT NULL;

    NOTE: If CREATE INDEX CONCURRENTLY fails on a partitioned table, create the indexes on each partition individually. This is a Postgres limitation — CONCURRENTLY doesn't work on partitioned tables in some versions. Regular CREATE INDEX (without CONCURRENTLY) will work but briefly locks writes.

STEP 5 — Full verification:

5a. Scale to 4 workers: docker compose up -d --scale worker=4
5b. Run integration test → 5/5
5c. Run harness → 20/20
5d. Verify Postgres config:
    docker exec <postgres-container> psql -U hydra -d hydra -c "SHOW max_connections;" → 200
5e. Verify PgBouncer pools:
    docker exec <pgbouncer-container> psql -p 6432 -U hydra pgbouncer -c "SHOW POOLS;"
5f. Verify partitioning:
    docker exec <postgres-container> psql -U hydra -d hydra -c "\d+ agent_tasks"
    → Should show "Partition key: RANGE (created_at)" and list child partitions
5g. Verify Redis:
    docker exec <redis-container> redis-cli PING → PONG
5h. Scale back to 1: docker compose up -d --scale worker=1

STEP 6 — Commit:
git add -A && git commit -m "Block 1.3: PgBouncer + Postgres tuning (max_conn=200, wal_level=replica, sync_commit=off) + Redis rate limiting + table partitioning"

=== RULES FOR THIS SESSION ===
- CREATE: config/postgresql.conf
- CREATE: worker/redis_client.py
- MODIFY: docker-compose.yml (add pgbouncer, add redis if missing, mount postgres config, update worker env)
- MODIFY: worker/activities.py (connection string if hardcoded there)
- MODIFY: worker/workflows.py (add rate limit check)
- RUN SQL: partitioning migration, auto-partition function, indexes
- DO NOT modify the Go API database connection
- DO NOT create load test scripts (that's session 1.4)
- DO NOT modify skill templates or test corpus
- If PgBouncer causes "prepared statement does not exist" errors, switch POOL_MODE to session and add a comment

STOP after commit and report: PgBouncer SHOW POOLS output, Postgres config verified, partitioning confirmed, Redis PING confirmed, rate limiting tested or TODO noted.
```

---

# ═══════════════════════════════════════════════
# SESSION 1.4a — Load Testing (Docker Compose)
# ═══════════════════════════════════════════════

**Prerequisite: Session 1.3 committed, PgBouncer + Redis working, 4-worker scaling verified.**

**Paste the shared context, then paste this:**

```
=== BLOCK 1 CONTEXT ===
Sessions 1.1-1.3 complete:
- Worker is stateless with worker_id tracking
- Multi-worker scaling works (docker compose --scale worker=N)
- PgBouncer handles connection pooling (max 50 DB connections, 400 client connections)
- Postgres tuned: max_connections=200, synchronous_commit=off, wal_level=replica
- Redis handles per-tenant rate limiting
- agent_tasks table partitioned by month

Now we prove it works under load.

=== PRE-FLIGHT CHECK ===
1. docker compose up -d --scale worker=4
2. docker ps → should show 4 workers, pgbouncer, redis, postgres, api, temporal all healthy
3. Quick smoke test: run integration test → 5/5

=== IMMEDIATE TASK: Load test script + scaling benchmarks ===

DO THIS IN ORDER:

STEP 1 — Create scripts/load_test.py:

This script runs FROM THE HOST (not inside a container) against localhost:8090.
Uses asyncio + httpx (or aiohttp) for concurrent HTTP requests.

Command line args:
  --concurrency N    (default 10, how many simultaneous investigations)
  --total N          (default 50, total investigations to submit)
  --ramp-up N        (default 10, seconds to ramp from 0 to full concurrency)
  --api-url URL      (default http://localhost:8090/api/v1)
  --output FILE      (default tests/results/load_test_results.json)

Investigation payloads: cycle through all 5 tested skill types.
For each, use the "easy" difficulty log from tests/corpus/{skill}/easy.log
Read log files from the host filesystem (tests/corpus/ directory).

Submission flow per investigation:
  1. POST /tasks with the log payload and appropriate task_type
  2. Poll GET /tasks/{id} every 2 seconds until status is "completed" or "failed" (timeout 120s)
  3. Record: task_id, task_type, worker_id, status, total_time_ms

Real-time terminal output during test:
  [00:05] Submitted: 15/50 | Completed: 8 | Failed: 0 | Running: 7 | Avg: 12.3s
  [00:10] Submitted: 30/50 | Completed: 22 | Failed: 0 | Running: 8 | Avg: 11.8s

Final summary:
  ╔══════════════════════════════════════════════════╗
  ║            HYDRA LOAD TEST RESULTS               ║
  ╠══════════════════════════════════════════════════╣
  ║ Total investigations:     50                     ║
  ║ Successful:               49                     ║
  ║ Failed:                   1                      ║
  ║ Error rate:               2.0%                   ║
  ║                                                  ║
  ║ Latency (end-to-end):                            ║
  ║   p50:                    8.2s                   ║
  ║   p95:                    22.1s                  ║
  ║   p99:                    45.3s                  ║
  ║   max:                    52.1s                  ║
  ║                                                  ║
  ║ Throughput:               4.2 inv/min            ║
  ║                                                  ║
  ║ Worker distribution:                             ║
  ║   worker-abc-1234:        14 tasks               ║
  ║   worker-def-5678:        13 tasks               ║
  ║   worker-ghi-9012:        12 tasks               ║
  ║   worker-jkl-3456:        11 tasks               ║
  ║                                                  ║
  ║ By skill:                                        ║
  ║   brute_force:     10 | avg 9.1s  | 0 fail      ║
  ║   ransomware:      10 | avg 11.2s | 0 fail      ║
  ║   lateral_movement:10 | avg 8.5s  | 1 fail      ║
  ║   c2:              10 | avg 10.3s | 0 fail      ║
  ║   phishing:        10 | avg 12.0s | 0 fail      ║
  ╚══════════════════════════════════════════════════╝

Save detailed results to JSON file.

STEP 2 — Run baseline load test (1 worker):
- docker compose up -d --scale worker=1
- Wait 30s for stabilization
- python scripts/load_test.py --concurrency 5 --total 20
- Record results

STEP 3 — Run scaled load test (4 workers):
- docker compose up -d --scale worker=4
- Wait 30s for all workers to register
- python scripts/load_test.py --concurrency 20 --total 50
- Record results

STEP 4 — Run stress test (4 workers, high concurrency):
- python scripts/load_test.py --concurrency 50 --total 100
- Record results — expect some degradation but no crashes or data corruption

STEP 5 — Monitor database during load (run these in a separate terminal during STEP 4):

Postgres connection usage:
  docker exec <postgres-container> psql -U hydra -d hydra -c "SELECT count(*) as total, count(*) FILTER (WHERE state = 'active') as active, count(*) FILTER (WHERE state = 'idle') as idle, count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_txn, count(*) FILTER (WHERE wait_event_type = 'Lock') as waiting FROM pg_stat_activity WHERE datname = 'hydra';"

PgBouncer pool usage:
  docker exec <pgbouncer-container> psql -p 6432 -U hydra pgbouncer -c "SHOW POOLS;"

Record:
- Peak total connections (must stay under 200)
- cl_waiting in PgBouncer (should be 0 — if >0, pool is too small)
- Any idle_in_txn (indicates connection leak)

STEP 6 — Verify data integrity after all load tests:

6a. No stuck tasks:
    docker exec <postgres-container> psql -U hydra -d hydra -c "SELECT status, COUNT(*) FROM agent_tasks GROUP BY status;"
    → All should be completed or failed, zero pending/running

6b. No missing worker_ids:
    docker exec <postgres-container> psql -U hydra -d hydra -c "SELECT COUNT(*) FROM agent_tasks WHERE status='completed' AND worker_id IS NULL;"
    → Must be 0

6c. Worker distribution:
    docker exec <postgres-container> psql -U hydra -d hydra -c "SELECT worker_id, COUNT(*) FROM agent_tasks WHERE status='completed' GROUP BY worker_id ORDER BY count DESC LIMIT 10;"

STEP 7 — Create docs/SCALING.md:

# Hydra Scaling Benchmark Results

## Test Environment
- Machine: [actual CPU, RAM, Docker Desktop memory allocation]
- Postgres: max_connections=200, shared_buffers=1GB, synchronous_commit=off
- PgBouncer: transaction mode, 50 DB connections, 400 client connections
- agent_tasks: partitioned by month

## 1 Worker Baseline
| Metric | Value |
|--------|-------|
| Concurrency | 5 |
| Total | 20 |
| p50 latency | [actual] |
| p95 latency | [actual] |
| Throughput | [actual] inv/min |
| Error rate | [actual]% |

## 4 Workers Scaled
| Metric | Value |
|--------|-------|
| Concurrency | 20 |
| Total | 50 |
| p50 | [actual] |
| p95 | [actual] |
| Throughput | [actual] inv/min |
| Error rate | [actual]% |
| Scaling factor vs 1 worker | [actual]x |

## 4 Workers Stress Test
| Metric | Value |
|--------|-------|
| Concurrency | 50 |
| Total | 100 |
| p50 | [actual] |
| p95 | [actual] |
| Throughput | [actual] inv/min |
| Error rate | [actual]% |

## Database Connection Analysis
| Metric | Peak During Stress Test |
|--------|----------------------|
| Postgres total connections | [actual] / 200 |
| Postgres active connections | [actual] |
| PgBouncer cl_active | [actual] |
| PgBouncer cl_waiting | [actual] |
| PgBouncer sv_active | [actual] / 50 |

## Capacity Planning
| Daily Investigations | Workers | Est. Monthly Compute |
|---------------------|---------|---------------------|
| 100 | 1 | $50 |
| 500 | 2 | $100 |
| 2,000 | 4 | $200 |
| 10,000 | 10 | $500 |
| 50,000 | 25 | $1,250 |
(Excludes LLM token costs)

## Known Bottlenecks
[Document observations: CPU-bound? DB-bound? LLM-latency-bound?]

## Scaling Instructions
docker compose up -d --scale worker=N
Workers auto-register with Temporal immediately.

STEP 8 — Commit:
git add -A && git commit -m "Block 1.4a: Load testing + Docker Compose scaling benchmarks"

=== RULES FOR THIS SESSION ===
- CREATE: scripts/load_test.py
- CREATE: docs/SCALING.md
- DO NOT modify worker code, docker-compose.yml, or any existing functionality
- The load test script must work on Windows PowerShell (no bash-only syntax)
- If httpx is not installed on host: pip install httpx
- If API requires auth, use same JWT mechanism as test_integration.py
- DO NOT modify the API to skip auth

STOP after commit and report: actual p50/p95/p99 for each test, scaling factor, any failures, DB connection analysis, identified bottlenecks.
```

---

# ═══════════════════════════════════════════════
# SESSION 1.4b — Kubernetes Manifests + HPA + NetworkPolicy
# ═══════════════════════════════════════════════

**Prerequisite: Session 1.4a committed. Load test results documented.**

**Paste the shared context, then paste this:**

```
=== BLOCK 1 CONTEXT ===
Sessions 1.1-1.4a complete. Docker Compose scaling works and is benchmarked. Now we build the Kubernetes deployment — this is what enterprise customers actually run.

=== IMMEDIATE TASK: Full Kubernetes manifest set with Kustomize overlays ===

DO THIS IN ORDER:

STEP 1 — Create directory structure:
k8s/
├── base/
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── postgres/
│   │   ├── statefulset.yaml
│   │   ├── service.yaml      # TWO services: postgres (primary/writes) + postgres-read (reads)
│   │   ├── configmap.yaml    # postgresql.conf with same tuning as Docker Compose
│   │   └── pvc.yaml
│   ├── pgbouncer/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── configmap.yaml
│   ├── redis/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── temporal/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   ├── litellm/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── configmap.yaml
│   ├── api/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── hpa.yaml
│   ├── worker/
│   │   ├── deployment.yaml
│   │   ├── hpa.yaml
│   │   └── networkpolicy.yaml
│   └── dashboard/
│       ├── deployment.yaml
│       └── service.yaml
├── overlays/
│   ├── dev/
│   │   └── kustomization.yaml
│   ├── production/
│   │   └── kustomization.yaml
│   └── airgap/
│       └── kustomization.yaml
└── README.md

STEP 2 — Worker Deployment:
- replicas: 2 in base (HPA overrides)
- securityContext: runAsNonRoot, runAsUser 1000, seccompProfile RuntimeDefault
- env WORKER_ID from fieldRef metadata.name (pod name = unique worker_id)
- env DATABASE_URL from secret (points to pgbouncer:6432)
- env REDIS_URL, TEMPORAL_HOST, TEMPORAL_TASK_QUEUE
- resources: requests 250m CPU / 256Mi RAM, limits 1 CPU / 512Mi RAM
- liveness + readiness probes
- terminationGracePeriodSeconds: 60 (let Temporal reassign in-flight tasks)
- Update worker/main.py to read WORKER_ID from env if present, fall back to hostname-pid format

STEP 3 — Worker NetworkPolicy (CRITICAL — this is the zero-trust proof):
- podSelector: component=worker
- policyTypes: Ingress + Egress
- ingress: [] (workers accept NO inbound connections)
- egress ONLY to:
  - pgbouncer:6432 (database via pool)
  - temporal:7233 (workflow engine)
  - redis:6379 (rate limiting + shared state)
  - litellm:4000 (LLM inference)
  - kube-dns:53 UDP+TCP (service name resolution)
- NOTHING ELSE. No internet. No API. No dashboard. No other namespaces.

STEP 4 — Worker HPA:
- scaleTargetRef: hydra-worker Deployment
- minReplicas: 2, maxReplicas: 50
- scaleUp: 4 pods per 60s, stabilization 30s (react fast to load)
- scaleDown: 2 pods per 120s, stabilization 300s (don't kill mid-investigation)
- metric: CPU utilization target 70%
- Add commented-out custom metric for Temporal queue depth (TODO for Block 6)

STEP 5 — Postgres StatefulSet:
- postgres:16-alpine image
- Mount postgresql.conf from ConfigMap (same tuning as Docker Compose: max_connections=200, shared_buffers=1GB, wal_level=replica, synchronous_commit=off)
- PVC: 50Gi ReadWriteOnce
- Resources: requests 500m CPU / 2Gi RAM, limits 4 CPU / 4Gi RAM (needs RAM for shared_buffers + connections)
- TWO Services:
  - "postgres" (primary, for writes) — selector: component=postgres
  - "postgres-read" (for dashboard/reporting reads) — same selector for now, change to role=replica when read replica added
- Headless service for StatefulSet

STEP 6 — API Deployment:
- 2 replicas in base
- HPA: min 2, max 10, CPU 70%
- Liveness/readiness: GET /healthz
- Resources: 250m-500m CPU, 256Mi-512Mi RAM
- Service: ClusterIP

STEP 7 — Remaining services:
- Redis: Deployment 1 replica, Service, healthcheck redis-cli ping
- Temporal: Deployment 1 replica, Service (ports 7233 + 8233 for UI)
- LiteLLM: Deployment 1 replica, Service, ConfigMap for model routing
- PgBouncer: Deployment 1 replica, Service, ConfigMap with same pool settings as Docker Compose
- Dashboard: Deployment 1 replica, Service

STEP 8 — Secrets template:
Create k8s/base/secrets.yaml.example (NOT the actual secrets file):
- hydra-db-credentials: password, pgbouncer-url, direct-url
- hydra-api-secrets: jwt-secret, openai-api-key
Add to .gitignore: k8s/**/secrets.yaml

STEP 9 — Kustomize overlays:

dev overlay:
- Worker replicas: 1, HPA min 1 max 4
- API replicas: 1
- Postgres resources reduced

production overlay:
- Worker replicas: 4, HPA min 2 max 50
- API replicas: 2
- Full resource allocations

airgap overlay:
- All images point to internal-registry.local:5000/hydra/*
- LiteLLM config switches to local Ollama endpoint
- No external image pulls

STEP 10 — README with:
- Quick start (dev): kubectl apply -k k8s/overlays/dev
- Production deployment steps
- Air-gap deployment steps
- Scaling instructions (HPA automatic + manual override)
- Security verification commands (kubectl get networkpolicy)
- Monitoring commands

STEP 11 — Read replica guide:
Create k8s/docs/READ_REPLICA_GUIDE.md documenting:
- When to add a read replica (>50 inv/min, or dashboard impacting writes)
- How to add one (replica StatefulSet + change postgres-read service selector)
- CloudNativePG operator recommendation for production
- Connection budget table with replica

STEP 12 — Validate:
- If kubectl available: kubectl apply -k k8s/overlays/dev --dry-run=client
- Otherwise verify all YAML is syntactically valid

STEP 13 — Commit:
git add -A && git commit -m "Block 1.4b: Kubernetes manifests — Kustomize + HPA (2-50 workers) + NetworkPolicy + 3 overlays (dev/prod/airgap)"

=== RULES FOR THIS SESSION ===
- CREATE: entire k8s/ directory structure
- MODIFY: worker/main.py ONLY to read WORKER_ID from env (one small change)
- MODIFY: .gitignore to exclude secrets
- DO NOT modify docker-compose.yml (Docker Compose and K8s are parallel paths)
- DO NOT modify worker logic, activities, workflows, skills, or tests
- DO NOT install kubectl or any K8s tooling — just create manifests
- All YAML must use consistent 2-space indentation
- Label everything: app=hydra, component={service-name}

STOP after commit and report: total manifest count, which services have HPA, NetworkPolicy egress rules, any validation issues.
```

---

# ═══════════════════════════════════════════════
# SESSION 1.5 — Kubernetes Deployment Verification
# ═══════════════════════════════════════════════

**Prerequisite: Session 1.4b committed. Docker Desktop Kubernetes OR minikube available.**

**If K8s is NOT available, skip this session. The manifests from 1.4b are still valuable. Come back when you have a cluster.**

**Paste the shared context, then paste this:**

```
=== BLOCK 1 CONTEXT ===
Sessions 1.1-1.4b complete. K8s manifests are in k8s/ directory. Now we deploy to a real cluster and prove it works.

=== PRE-FLIGHT CHECK ===
1. kubectl cluster-info → must show a running cluster
2. kubectl get nodes → must show at least one Ready node
If either fails, STOP. Cannot proceed without a working cluster.

=== IMMEDIATE TASK: Deploy + verify + load test on K8s ===

DO THIS IN ORDER:

STEP 1 — Build and tag Docker images:
- docker build -t hydra/api:latest -f api/Dockerfile .
- docker build -t hydra/worker:latest -f worker/Dockerfile .
- docker build -t hydra/dashboard:latest -f dashboard/Dockerfile .
  (adjust Dockerfile paths based on actual project structure)
- If using minikube: eval $(minikube docker-env) first

STEP 2 — Deploy dev overlay:
- kubectl apply -k k8s/overlays/dev
- kubectl get pods -n hydra -w (wait until all Running + Ready)
- If pods crash, check: kubectl logs -n hydra <pod-name>
- Common fixes:
  a) Image pull error → image not built or tagged wrong
  b) CrashLoopBackOff on worker → check TEMPORAL_HOST, DATABASE_URL env vars
  c) PVC Pending → storage class issue, try hostPath for dev
  d) Temporal crash → needs postgres to be ready first (check depends ordering or just wait for restart)

STEP 3 — Verify basic functionality:
- kubectl port-forward -n hydra svc/hydra-api 8090:8090 &
- Run integration test: python scripts/test_integration.py (HYDRA_API_URL=http://localhost:8090/api/v1)
- Must pass 5/5

STEP 4 — Verify NetworkPolicy:
- kubectl get networkpolicy -n hydra → should show hydra-worker-netpol

- Test internet blocked from worker:
  kubectl exec -n hydra deployment/hydra-worker -- python -c "import urllib.request; urllib.request.urlopen('https://google.com', timeout=5)" 2>&1
  MUST fail with timeout/connection error

- Test PgBouncer access allowed:
  kubectl exec -n hydra deployment/hydra-worker -- python -c "import psycopg2; c=psycopg2.connect('postgres://hydra:hydra_dev_2026@pgbouncer:6432/hydra'); print('Connected OK')"
  MUST succeed

NOTE: Docker Desktop's default CNI may not enforce NetworkPolicy. If the internet test SUCCEEDS, document: "NetworkPolicy applied but not enforced — requires Calico/Cilium CNI in production." This is expected on Docker Desktop. The policy is still correct and will enforce on a production cluster.

STEP 5 — Deploy production overlay:
- kubectl apply -k k8s/overlays/production
- kubectl get pods -n hydra -l component=worker → should show 4 pods
- kubectl get pods -n hydra -l component=api → should show 2 pods
- kubectl get hpa -n hydra → should show hydra-worker-hpa with current CPU metrics

STEP 6 — Load test on K8s:
- Keep port-forward running
- python scripts/load_test.py --concurrency 20 --total 50 --api-url http://localhost:8090/api/v1
- In a separate terminal, watch HPA: kubectl get hpa -n hydra -w
- In another terminal, watch pods: kubectl get pods -n hydra -l component=worker -w
- Record results

STEP 7 — Stress test + auto-scaling:
- python scripts/load_test.py --concurrency 50 --total 200 --api-url http://localhost:8090/api/v1
- Watch if HPA scales up workers
- Record:
  a) Peak worker pod count
  b) Time from first HPA trigger to new pod Running
  c) p95 during scale-up vs after stabilization
  d) Any OOM kills: kubectl get events -n hydra --sort-by='.lastTimestamp' | grep -i oom

STEP 8 — Monitor Postgres during load:
  kubectl exec -n hydra statefulset/hydra-postgres -- psql -U hydra -d hydra -c "SELECT count(*) as total, count(*) FILTER (WHERE state='active') as active, count(*) FILTER (WHERE state='idle') as idle, count(*) FILTER (WHERE state='idle in transaction') as idle_in_txn FROM pg_stat_activity WHERE datname='hydra';"

  kubectl exec -n hydra deployment/hydra-pgbouncer -- psql -p 6432 -U hydra pgbouncer -c "SHOW POOLS;"

STEP 9 — Data integrity check:
  kubectl exec -n hydra statefulset/hydra-postgres -- psql -U hydra -d hydra -c "SELECT status, COUNT(*) FROM agent_tasks GROUP BY status;"
  → Zero stuck tasks

  kubectl exec -n hydra statefulset/hydra-postgres -- psql -U hydra -d hydra -c "SELECT COUNT(*) FROM agent_tasks WHERE status='completed' AND worker_id IS NULL;"
  → Must be 0

  kubectl exec -n hydra statefulset/hydra-postgres -- psql -U hydra -d hydra -c "SELECT worker_id, COUNT(*) FROM agent_tasks WHERE status='completed' GROUP BY worker_id ORDER BY count DESC LIMIT 10;"
  → Distribution across multiple K8s pod names

STEP 10 — Update docs/SCALING.md with K8s section:

## Kubernetes Scaling Results

### Test Environment
- Cluster: [Docker Desktop K8s / minikube / cloud]
- Node resources: [CPU, RAM]

### Comparison: Docker Compose vs Kubernetes (4 workers)
| Metric | Docker Compose | Kubernetes |
|--------|---------------|------------|
| p50 | [from 1.4a] | [actual] |
| p95 | [from 1.4a] | [actual] |
| Throughput | [from 1.4a] | [actual] |
| Error rate | [from 1.4a] | [actual] |

### Auto-Scaling (stress test)
| Metric | Value |
|--------|-------|
| Starting replicas | 4 |
| Peak replicas (HPA) | [actual] |
| Time to first scale-up | [actual]s |
| p95 during scale-up | [actual] |
| p95 after stabilization | [actual] |

### NetworkPolicy Verification
| Test | Result |
|------|--------|
| Worker → Internet | BLOCKED ✓ (or note CNI limitation) |
| Worker → PgBouncer | ALLOWED ✓ |
| Worker → Temporal | ALLOWED ✓ |
| Worker → Redis | ALLOWED ✓ |
| Worker → LiteLLM | ALLOWED ✓ |
| Inbound → Worker | BLOCKED ✓ |

### Database Connections Under K8s Load
| Metric | Peak |
|--------|------|
| Postgres total connections | [actual] / 200 |
| PgBouncer cl_waiting | [actual] |
| PgBouncer sv_active | [actual] / 50 |

STEP 11 — Clean up:
  kubectl delete -k k8s/overlays/production (or leave running for demo)

STEP 12 — Commit:
git add -A && git commit -m "Block 1.5: K8s deployment verified — HPA scaling to [N] pods + NetworkPolicy enforced + load test results"

=== RULES FOR THIS SESSION ===
- MODIFY: docs/SCALING.md (add K8s results section)
- MODIFY: k8s/ manifests ONLY to fix issues discovered during deployment
- MODIFY: scripts/load_test.py ONLY if needed for port-forwarded API
- DO NOT modify worker code, docker-compose.yml, or application logic
- If K8s deployment fails due to resource constraints, reduce dev overlay resources and document it
- If HPA doesn't trigger (LLM calls are I/O-bound, not CPU-bound), document and add TODO for custom queue depth metric

STOP after commit and report: K8s deploy status, NetworkPolicy enforcement, HPA behavior, Docker Compose vs K8s comparison numbers.
```

---

# ═══════════════════════════════════════════════
# POST-BLOCK 1 CHECKLIST
# ═══════════════════════════════════════════════

```
After all sessions, verify before moving to Block 2:

Docker Compose:
□ worker_id populated on all completed tasks
□ docker compose --scale worker=4 boots cleanly
□ 20/20 harness passes at any worker count
□ 5/5 integration passes through PgBouncer
□ Postgres: max_connections=200, shared_buffers=1GB, wal_level=replica, synchronous_commit=off
□ PgBouncer: SHOW POOLS shows connection reuse, cl_waiting=0 under load
□ Redis: rate limiting prevents over-limit submissions
□ agent_tasks: partitioned by month, auto-partition function created
□ Load test: 50 concurrent at 4 workers, <5% errors
□ Scaling factor: 4 workers ≥ 3x throughput of 1 worker
□ Zero stuck tasks after load test
□ Zero NULL worker_ids on completed tasks

Kubernetes:
□ k8s/base/ manifests for all services
□ 3 Kustomize overlays: dev, production, airgap
□ Worker NetworkPolicy: egress ONLY to pgbouncer + temporal + redis + litellm + DNS
□ Worker HPA: min 2, max 50, CPU 70%
□ API HPA: min 2, max 10
□ Postgres: StatefulSet with custom config ConfigMap + PVC + dual services (primary + read)
□ Secrets template (not committed, in .gitignore)
□ k8s/README.md with deploy instructions for all 3 modes
□ k8s/docs/READ_REPLICA_GUIDE.md
□ (If K8s available) Dev overlay deploys, integration test passes
□ (If K8s available) Production overlay auto-scales under load
□ (If K8s available) NetworkPolicy blocks worker internet access

Documentation:
□ docs/SCALING.md with Docker Compose AND K8s benchmark numbers
□ Database connection analysis section
□ Capacity planning table
□ Known bottlenecks documented
□ All 5-6 commits in git log
```
