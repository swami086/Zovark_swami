# HYDRA Sprint 1J — Autoscaling + Rate Limit Fix
## Claude Code Prompt

---

You are building Sprint 1J for HYDRA, an AI-powered SOC investigation automation platform. This sprint replaces CPU-based HPA with Temporal queue depth scaling (workers are I/O-bound, not CPU-bound) and fixes the rate limit counter leak with a lease-based approach.

## Context

Current state:
- Workers scale via `docker compose --scale worker=N` or K8s HPA targeting 70% CPU
- But workers spend 80%+ time waiting on LLM inference — CPU is near-idle during LLM calls
- Rate limiting uses Redis INCR/DECR with 1-hour TTL safety net, but if a worker crashes mid-task, the counter leaks (TTL is a band-aid, not a fix)

## Deliverables

### 1J-1: Temporal Queue Depth Metrics Exporter

Create `monitoring/temporal_exporter.py` (or Go equivalent):

1. Query Temporal's visibility API for pending task count:
   - Temporal SDK or HTTP API to get task queue backlog
   - Metric: `hydra_temporal_pending_tasks{queue="hydra-tasks"}` — gauge
   - Metric: `hydra_temporal_active_tasks{queue="hydra-tasks"}` — gauge
   - Metric: `hydra_temporal_tasks_per_worker` — gauge (pending / active workers)

2. Expose as Prometheus endpoint on port 9092

3. Add to Docker Compose as a lightweight sidecar container
   - Scrape interval: 15 seconds
   - Only needs access to Temporal (temporal:7233)

4. Add scrape config to Prometheus (if Sprint 1F is done, update existing; otherwise create prometheus.yml):
```yaml
  - job_name: 'temporal-exporter'
    static_configs:
      - targets: ['temporal-exporter:9092']
    scrape_interval: 15s
```

### 1J-2: KEDA ScaledObject for Kubernetes

Create `k8s/base/keda-scaledobject.yaml`:

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: hydra-worker-scaler
spec:
  scaleTargetRef:
    name: hydra-worker
  minReplicaCount: 2
  maxReplicaCount: 50
  pollingInterval: 15
  cooldownPeriod: 120
  triggers:
    - type: prometheus
      metadata:
        serverAddress: http://prometheus:9090
        metricName: hydra_temporal_pending_tasks
        query: hydra_temporal_pending_tasks{queue="hydra-tasks"}
        threshold: "5"  # scale up when > 5 pending tasks per worker
```

Also create a fallback CPU-based HPA in case KEDA is not installed:
- Keep existing HPA but set it as secondary (lower priority than KEDA)
- Document: "Use KEDA if available, fall back to CPU HPA otherwise"

Update Kustomize overlays:
- `k8s/overlays/dev/`: KEDA disabled, single worker
- `k8s/overlays/production/`: KEDA enabled, min 4 workers
- `k8s/overlays/airgap/`: KEDA enabled, min 2 workers

### 1J-3: Lease-Based Rate Limiting

Replace the current INCR/DECR pattern with lease-based rate limiting.

Current pattern (broken):
```python
# Start of task
INCR tenant:{id}:active
# End of task (finally block)
DECR tenant:{id}:active
# Problem: if worker crashes between INCR and DECR, counter leaks
# Band-aid: 1-hour TTL on the counter
```

New pattern (self-healing):
```python
# Acquire lease
lease_key = f"tenant:{tenant_id}:lease:{task_id}"
acquired = redis.set(lease_key, worker_id, ex=60, nx=True)  # 60s lease, create only if not exists
if not acquired:
    raise RateLimitExceeded()

# Count active leases
active = len(redis.keys(f"tenant:{tenant_id}:lease:*"))  # or use SCAN
if active > MAX_CONCURRENT:
    redis.delete(lease_key)
    raise RateLimitExceeded()

# During task: heartbeat extends lease
async def heartbeat():
    while task_running:
        redis.expire(lease_key, 60)  # extend lease
        await asyncio.sleep(20)  # heartbeat every 20s

# End of task: release lease
redis.delete(lease_key)

# If worker crashes: lease auto-expires in 60s, slot is reclaimed
```

Implementation:

1. Create `worker/rate_limiter.py`:
   - `acquire_lease(tenant_id, task_id, worker_id, max_concurrent=50) -> bool`
   - `release_lease(tenant_id, task_id)`
   - `heartbeat_lease(tenant_id, task_id, ttl=60)`
   - `get_active_count(tenant_id) -> int`
   - `cleanup_expired_leases(tenant_id)` — called periodically, SCAN for expired keys

2. Update `check_rate_limit_activity` in activities.py:
   - Replace INCR pattern with `acquire_lease()`
   - Return lease info in result dict

3. Update `decrement_active_activity` in activities.py:
   - Replace DECR with `release_lease()`

4. Add heartbeat to the workflow:
   - Between long-running activities (LLM calls, sandbox execution), call `heartbeat_lease()`
   - Use Temporal activity heartbeat mechanism if possible, or explicit heartbeat activity

5. Add Lua script for atomic lease acquisition + count check:
```lua
-- KEYS[1] = lease key, KEYS[2] = tenant lease pattern
-- ARGV[1] = worker_id, ARGV[2] = ttl, ARGV[3] = max_concurrent
local acquired = redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX')
if not acquired then
    return -1  -- lease already held
end
local count = #redis.call('KEYS', KEYS[2])
if count > tonumber(ARGV[3]) then
    redis.call('DEL', KEYS[1])
    return -2  -- over limit
end
return count
```

Note: `KEYS` command in Lua has performance concerns at scale. For production with 1000+ concurrent, switch to a Redis sorted set with timestamps. For now (< 100 concurrent), KEYS in Lua is acceptable.

### 1J-4: Docker Compose Autoscaling (Development)

For Docker Compose (no K8s), add a simple autoscaler script:

Create `scripts/autoscale.py`:
- Poll Temporal queue depth every 15 seconds
- If pending > threshold: `docker compose up -d --scale worker=N` (N = current + 2, max 10)
- If pending == 0 for 5 minutes: scale down (min 1)
- Configurable via env vars: `AUTOSCALE_MIN=1 AUTOSCALE_MAX=10 AUTOSCALE_THRESHOLD=5`
- Runs as a standalone process (not in Docker)

### 1J-5: Rate Limit Metrics

Add metrics:
- `hydra_rate_limit_leases_active{tenant}` — gauge
- `hydra_rate_limit_lease_acquisitions_total{tenant, result}` — counter (result: acquired, rejected, expired)
- `hydra_rate_limit_lease_ttl_extensions_total{tenant}` — counter (heartbeats)
- `hydra_autoscale_workers_current` — gauge
- `hydra_autoscale_events_total{action}` — counter (action: scale_up, scale_down)

## Important Constraints

- Lease-based rate limiting must be backward compatible — if Redis is unavailable, fall back to no rate limiting (fail open for availability, log warning)
- The KEYS command in Lua is acceptable for < 100 concurrent tasks. Add a TODO comment for sorted set migration at scale.
- KEDA is an optional dependency — K8s manifests must work without it (fallback HPA)
- Temporal queue depth exporter must handle Temporal being temporarily unavailable (retry with backoff)
- All changes must work in Docker Compose AND Kubernetes

## Definition of Done

- [ ] Temporal queue depth metric visible in Prometheus
- [ ] KEDA ScaledObject in K8s manifests, validated via kustomize build
- [ ] Lease-based rate limiting: kill a worker mid-task, verify lease expires and slot is reclaimed within 60s
- [ ] Heartbeat: verify lease doesn't expire during long-running investigations
- [ ] Docker Compose autoscaler: `python scripts/autoscale.py` scales workers based on queue depth
- [ ] Rate limit metrics in Prometheus
- [ ] All existing tests still pass
- [ ] Git commit: "Sprint 1J: KEDA autoscaling + lease-based rate limiting"
