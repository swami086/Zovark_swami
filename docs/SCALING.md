# HYDRA Horizontal Scaling Guide

## Architecture Overview

HYDRA workers are **fully stateless** — all state lives in PostgreSQL (persistent), Redis (ephemeral counters), and Temporal (workflow state). This enables horizontal scaling by simply adding more worker instances.

```
                    ┌─────────────┐
                    │   API (Go)  │
                    └──────┬──────┘
                           │ Temporal
                    ┌──────▼──────┐
                    │   Temporal   │
                    │   Server     │
                    └──────┬──────┘
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ Worker 1 │ │ Worker 2 │ │ Worker N │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │             │             │
        ┌────▼─────────────▼─────────────▼────┐
        │           PgBouncer                  │
        │   (transaction pooling, 400 conn)    │
        └──────────────┬──────────────────────┘
                       ▼
              ┌─────────────────┐
              │   PostgreSQL    │
              │  (partitioned)  │
              └─────────────────┘
```

## Worker Identity

Each worker generates a unique identity on startup:
- Format: `{hostname}-{pid}-{random4chars}` (e.g., `9342178bfbab-1-vca5`)
- Override via `WORKER_ID` env var (e.g., Kubernetes pod name)
- Recorded on every task for traceability

## Scaling with Docker Compose

```bash
# Scale to N workers
docker compose up -d --scale worker=N

# Scale back to 1
docker compose up -d --scale worker=1

# Check worker count
docker compose ps | grep worker
```

**Important**: The `worker` service has no `container_name` set, which allows Docker Compose to create multiple instances.

## Connection Pooling (PgBouncer)

Workers connect through PgBouncer for connection pooling:

| Parameter           | Value |
|---------------------|-------|
| Pool Mode           | transaction |
| Max Client Conn     | 400   |
| Default Pool Size   | 25    |
| Min Pool Size       | 5     |
| Reserve Pool Size   | 20    |
| Max DB Connections   | 50    |

Workers use `DATABASE_URL=postgresql://hydra:...@pgbouncer:5432/hydra`.

## Rate Limiting

Per-tenant concurrent investigation limits via Redis atomic counters:
- Default: 50 concurrent investigations per tenant
- Key pattern: `hydra:active:{tenant_id}`
- Safety: 1-hour TTL auto-expiry prevents counter drift
- Implementation: `check_rate_limit_activity` / `decrement_active_activity` (Temporal activities)

## Table Partitioning

`agent_tasks` is RANGE-partitioned on `created_at`:
- Monthly partitions (auto-created via `fn_auto_partition_agent_tasks()`)
- Current partitions: 2026_03 through 2026_06
- Performance indexes: `idx_tasks_tenant_status`, `idx_tasks_skill_created`, `idx_tasks_worker`

## PostgreSQL Tuning

Key settings (`config/postgresql.conf`):

| Setting              | Value  | Rationale |
|----------------------|--------|-----------|
| max_connections      | 200    | PgBouncer handles client connections |
| shared_buffers       | 1GB    | ~25% of available RAM |
| effective_cache_size | 3GB    | OS page cache estimate |
| work_mem             | 16MB   | Per-sort memory |
| synchronous_commit   | off    | Faster writes, acceptable for analytics |
| password_encryption  | md5    | PgBouncer compatibility |

## Load Test Results

### Test Environment
- Machine: Windows 11, RTX 3050 4GB
- LLM: Qwen2.5-1.5B-Instruct-AWQ via LiteLLM/OpenRouter
- DB: PostgreSQL 16 + pgvector + PgBouncer
- Workflow: Temporal 1.24.2

### Baseline (1 Worker)

| Metric       | Value     |
|--------------|-----------|
| Total        | 20        |
| Success Rate | 100%      |
| p50 Latency  | 12.1s     |
| p95 Latency  | 30.1s     |
| Throughput   | 17.1 inv/min |

### Scaled (4 Workers)

| Metric       | Value     |
|--------------|-----------|
| Total        | 50        |
| Success Rate | 100%      |
| p50 Latency  | 16.1s     |
| p95 Latency  | 36.2s     |
| p99 Latency  | 38.4s     |
| Throughput   | 20.9 inv/min |

### Stress Test (4 Workers, 50 Concurrent)

| Metric       | Value     |
|--------------|-----------|
| Total        | 100       |
| Success Rate | 71%       |
| p50 Latency  | 14.0s     |
| p95 Latency  | 35.0s     |
| p99 Latency  | 64.6s     |
| Throughput   | 9.9 inv/min |
| Error Source | Rate limiter (by design) |

### Per-Skill Latency (Scaled Test)

| Skill              | Avg Latency | Notes |
|--------------------|-------------|-------|
| ransomware         | 9.4s        | Fastest (template match) |
| brute_force        | 16.0s       | |
| lateral_movement   | 16.5s       | |
| phishing           | 20.6s       | |
| c2                 | 30.0s       | Slowest (complex analysis) |

## Scaling Recommendations

| Workers | Concurrency | Expected Throughput |
|---------|-------------|---------------------|
| 1       | 5           | ~17 inv/min         |
| 4       | 20          | ~21 inv/min         |
| 8       | 40          | ~30 inv/min (est)   |
| 16      | 80          | ~45 inv/min (est)   |

**Bottleneck**: LLM inference throughput is the primary constraint. Adding workers helps when LLM can handle the load. With a larger GPU (e.g., RTX 4090), throughput scales more linearly with worker count.

## Kubernetes Deployment

See `k8s/` directory for:
- Deployment manifests with HPA (Horizontal Pod Autoscaler)
- NetworkPolicy for service isolation
- Kustomize overlays for dev/staging/prod
