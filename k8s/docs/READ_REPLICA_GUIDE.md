# PostgreSQL Read Replica Guide

## When to Add a Read Replica

Add a read replica when any of these conditions apply:
- Throughput exceeds **50 investigations/minute** sustained
- Dashboard queries cause noticeable latency on write operations
- `pg_stat_activity` shows >100 concurrent connections consistently
- Query response time for reporting exceeds 500ms

## How to Add a Read Replica

### 1. Create Replica StatefulSet

Create `k8s/base/postgres/replica-statefulset.yaml`:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres-replica
  namespace: zovark
  labels:
    app: zovark
    component: postgres
    role: replica
spec:
  serviceName: postgres-replica-headless
  replicas: 1
  selector:
    matchLabels:
      app: zovark
      component: postgres
      role: replica
  template:
    metadata:
      labels:
        app: zovark
        component: postgres
        role: replica
    spec:
      containers:
        - name: postgres
          image: pgvector/pgvector:pg16
          env:
            - name: PGDATA
              value: /var/lib/postgresql/data/pgdata
          command:
            - bash
            - -c
            - |
              pg_basebackup -h postgres -U zovark -D /var/lib/postgresql/data/pgdata -Fp -Xs -P -R
              postgres -c config_file=/etc/postgresql/postgresql.conf
```

### 2. Update `postgres-read` Service Selector

Change `k8s/base/postgres/service.yaml` postgres-read service:

```yaml
# Change from:
selector:
  app: zovark
  component: postgres

# Change to:
selector:
  app: zovark
  component: postgres
  role: replica
```

### 3. Point Dashboard at Read Replica

Update dashboard deployment to use `postgres-read:5432` for read queries.

## Production Recommendation: CloudNativePG

For production deployments, use the [CloudNativePG](https://cloudnative-pg.io/) operator:

```bash
kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.22/releases/cnpg-1.22.0.yaml
```

Benefits:
- Automated failover and self-healing
- Declarative replica management
- Automated backups to S3/MinIO
- Rolling updates with zero downtime
- Built-in connection pooling (PgBouncer sidecar)

## Connection Budget Table

| Component      | Without Replica | With Replica |
|----------------|-----------------|--------------|
| Workers (write)| PgBouncer → Primary (50 pool) | PgBouncer → Primary (50 pool) |
| Dashboard (read)| PgBouncer → Primary | postgres-read → Replica |
| API (mixed)    | PgBouncer → Primary | PgBouncer → Primary (writes), postgres-read → Replica (reads) |
| Total primary  | ~200 connections | ~100 connections |
| Total replica  | N/A              | ~100 connections |
