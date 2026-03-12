# HYDRA Disaster Recovery Runbook

## RTO/RPO Targets

| Tier | RTO (Recovery Time) | RPO (Data Loss) | Description |
|------|-------------------|-----------------|-------------|
| Tier 1 (Critical) | 15 minutes | 0 (synchronous) | PostgreSQL primary, API gateway |
| Tier 2 (High) | 30 minutes | 5 minutes | Workers, Temporal, Redis |
| Tier 3 (Standard) | 2 hours | 1 hour | Dashboard, monitoring, LiteLLM |
| Tier 4 (Low) | 8 hours | 24 hours | MinIO backups, historical data |

## Backup Verification Procedures

### Daily Automated Checks

1. **Database Backup Integrity**
   ```bash
   # Verify latest backup can be restored
   ./scripts/backup-db.sh

   # Restore to a test database (non-destructive)
   export POSTGRES_DB=hydra_dr_test
   ./scripts/restore-db.sh daily <latest-backup>

   # Verify table counts match
   psql -h localhost -U hydra -d hydra_dr_test -c \
     "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public';"
   ```

2. **MinIO Backup Verification**
   ```bash
   mc ls hydra/hydra-backups/daily/ | tail -1
   mc stat hydra/hydra-backups/daily/<latest>
   ```

3. **Temporal State Verification**
   ```bash
   tctl workflow list --status open | head -5
   tctl namespace describe hydra-tasks
   ```

### Weekly Manual Checks

- [ ] Restore a full backup to isolated environment
- [ ] Verify all migrations apply cleanly
- [ ] Test API health endpoint responds
- [ ] Verify investigation data integrity (sample 5 investigations)
- [ ] Check MinIO bucket replication status
- [ ] Review backup retention (7 daily + 4 weekly present)

### Monthly Drill

- [ ] Full DR failover to secondary region
- [ ] Measure actual RTO achieved
- [ ] Verify RPO by comparing data timestamps
- [ ] Document any issues encountered
- [ ] Update runbook with lessons learned

## Failover Procedures

### Scenario 1: PostgreSQL Primary Failure

**Detection:** Prometheus alert `PostgresDown` fires, API returns 503.

**Steps:**

1. **Verify failure is real** (not transient)
   ```bash
   pg_isready -h postgres-primary -U hydra -d hydra
   ```

2. **Promote read replica**
   ```bash
   # On the replica host
   pg_ctl promote -D /var/lib/postgresql/data
   ```

3. **Update connection strings**
   ```bash
   # Update Kubernetes secret
   kubectl create secret generic hydra-db-credentials \
     --from-literal=direct-url="postgresql://hydra:<pass>@<new-primary>:5432/hydra" \
     --from-literal=pgbouncer-url="postgresql://hydra:<pass>@<new-primary>:5432/hydra" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

4. **Restart dependent services**
   ```bash
   kubectl rollout restart deployment/hydra-api -n hydra
   kubectl rollout restart deployment/hydra-worker -n hydra
   ```

5. **Verify recovery**
   ```bash
   curl -s http://hydra-api:8090/health | jq .
   ```

### Scenario 2: API Gateway Failure

**Detection:** Health check failures, HTTP 502/503 from ingress.

**Steps:**

1. **Check pod status**
   ```bash
   kubectl get pods -l component=api -n hydra
   kubectl describe pod <failing-pod> -n hydra
   ```

2. **If OOMKilled:** Increase memory limits
   ```bash
   kubectl set resources deployment/hydra-api --limits=memory=1Gi -n hydra
   ```

3. **If CrashLoopBackOff:** Check logs and rollback
   ```bash
   kubectl logs -l component=api -n hydra --tail=50
   kubectl rollout undo deployment/hydra-api -n hydra
   ```

4. **If all pods down:** Scale from zero
   ```bash
   kubectl scale deployment/hydra-api --replicas=0 -n hydra
   kubectl scale deployment/hydra-api --replicas=3 -n hydra
   ```

### Scenario 3: Worker Failure (Temporal Tasks Stuck)

**Detection:** Temporal UI shows workflows in "Running" state beyond SLA.

**Steps:**

1. **Check worker health**
   ```bash
   kubectl get pods -l component=worker -n hydra
   kubectl logs -l component=worker -n hydra --tail=20
   ```

2. **Restart workers**
   ```bash
   kubectl rollout restart deployment/hydra-worker -n hydra
   ```

3. **If Temporal queue is backed up:**
   ```bash
   # Scale up workers temporarily
   kubectl scale deployment/hydra-worker --replicas=10 -n hydra
   ```

4. **If workflows are stuck permanently:**
   ```bash
   # Terminate stuck workflows (use with caution)
   tctl workflow terminate -w <workflow-id> -r <run-id>
   ```

### Scenario 4: Complete Region Failure

**Detection:** All health checks from region fail, DNS health checks trigger.

**Steps:**

1. **Execute automated failover**
   ```bash
   ./scripts/dr-failover.sh <target-region>
   ```

2. **Manual DNS switch** (if automated fails)
   ```bash
   # Update Route 53 / DNS to point to secondary region
   aws route53 change-resource-record-sets --hosted-zone-id <zone> \
     --change-batch file://dns-failover.json
   ```

3. **Verify secondary region**
   ```bash
   curl -s https://hydra.example.com/health
   ```

4. **Notify stakeholders** (see Communication Plan below)

### Scenario 5: Redis Failure

**Detection:** Cache miss rate spikes, worker rate limiting fails.

**Steps:**

1. **Check Redis status**
   ```bash
   redis-cli -h redis ping
   kubectl get pods -l component=redis -n hydra
   ```

2. **Restart Redis**
   ```bash
   kubectl rollout restart deployment/redis -n hydra
   ```

3. **Impact:** Workers will function without Redis (rate limiting disabled, cache cold). No data loss expected.

## Communication Plan

### Severity Levels

| Level | Criteria | Notification |
|-------|----------|-------------|
| SEV-1 | Complete outage, data at risk | Immediate: Slack #hydra-incidents, PagerDuty, email to all stakeholders |
| SEV-2 | Degraded service, no data loss | Within 15 min: Slack #hydra-incidents, email to engineering leads |
| SEV-3 | Single component failure, auto-healing | Within 1 hour: Slack #hydra-ops |
| SEV-4 | Performance degradation | Next business day: Jira ticket |

### Stakeholder Contacts

| Role | Contact Method | When to Notify |
|------|---------------|----------------|
| On-call Engineer | PagerDuty | SEV-1, SEV-2 |
| Engineering Lead | Slack + Email | SEV-1, SEV-2 |
| Security Team | Slack #security | All SEV-1, security-related SEV-2 |
| Customer Success | Email | SEV-1 (customer-impacting) |
| Executive Team | Email summary | SEV-1 (>30 min outage) |

### Communication Templates

**Initial Notification:**
```
[HYDRA Incident] SEV-<N>: <Brief Description>
Time: <timestamp UTC>
Impact: <what is affected>
Status: Investigating / Mitigating / Resolved
ETA: <estimated resolution time>
```

**Status Update (every 30 min for SEV-1):**
```
[HYDRA Incident Update] <Incident ID>
Current Status: <status>
Actions Taken: <list>
Next Steps: <list>
ETA: <updated estimate>
```

## Post-Incident Review Template

### Incident Report: [HYDRA-YYYY-MMDD-NNN]

**Date:** YYYY-MM-DD
**Duration:** HH:MM
**Severity:** SEV-N
**Lead:** [Name]

#### Timeline
| Time (UTC) | Event |
|------------|-------|
| HH:MM | Incident detected |
| HH:MM | Team assembled |
| HH:MM | Root cause identified |
| HH:MM | Fix applied |
| HH:MM | Service restored |

#### Root Cause
[Description of what caused the incident]

#### Impact
- Users affected: N
- Investigations delayed: N
- Data loss: Yes/No (details)

#### What Went Well
- [List items]

#### What Needs Improvement
- [List items]

#### Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| | | | |

#### Metrics
- Time to detect: X minutes
- Time to respond: X minutes
- Time to resolve: X minutes
- Actual RTO: X minutes
- Actual RPO: X minutes (data loss window)
