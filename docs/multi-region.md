# ZOVARC Multi-Region Deployment Architecture

## Overview

Multi-region deployment enables ZOVARC to operate across geographically distributed regions for high availability, data sovereignty, and reduced latency. This document covers the architecture, configuration, and operational procedures.

## Architecture Diagram

```
                         ┌──────────────────┐
                         │   DNS (Route 53)  │
                         │  zovarc.example.com│
                         │  Latency-based    │
                         └──────┬───────────┘
                                │
               ┌────────────────┼────────────────┐
               │                │                │
    ┌──────────▼──────────┐  ┌──▼──────────────┐  ┌──────────▼──────────┐
    │   US-EAST-1 (Primary)│  │   EU-WEST-1      │  │   AP-SOUTHEAST-1   │
    │                      │  │   (Secondary)     │  │   (Secondary)      │
    │  ┌──────────────┐   │  │  ┌─────────────┐ │  │  ┌─────────────┐  │
    │  │   Ingress     │   │  │  │   Ingress    │ │  │  │   Ingress    │  │
    │  │   (Caddy/ALB) │   │  │  │   (Caddy/ALB)│ │  │  │   (Caddy/ALB)│  │
    │  └──────┬───────┘   │  │  └──────┬──────┘ │  │  └──────┬──────┘  │
    │         │            │  │         │         │  │         │         │
    │  ┌──────▼───────┐   │  │  ┌──────▼──────┐ │  │  ┌──────▼──────┐  │
    │  │  API Gateway  │   │  │  │  API Gateway │ │  │  │  API Gateway │  │
    │  │  (2 replicas) │   │  │  │  (2 replicas)│ │  │  │  (2 replicas)│  │
    │  └──────┬───────┘   │  │  └──────┬──────┘ │  │  └──────┬──────┘  │
    │         │            │  │         │         │  │         │         │
    │  ┌──────▼───────┐   │  │  ┌──────▼──────┐ │  │  ┌──────▼──────┐  │
    │  │   Workers     │   │  │  │   Workers    │ │  │  │   Workers    │  │
    │  │  (2-20 HPA)   │   │  │  │  (2-20 HPA) │ │  │  │  (2-20 HPA) │  │
    │  └──────┬───────┘   │  │  └──────┬──────┘ │  │  └──────┬──────┘  │
    │         │            │  │         │         │  │         │         │
    │  ┌──────▼───────┐   │  │  ┌──────▼──────┐ │  │  ┌──────▼──────┐  │
    │  │ PostgreSQL    │   │  │  │ PostgreSQL   │ │  │  │ PostgreSQL   │  │
    │  │ PRIMARY (RW)  │◄─┼──┼─►│ REPLICA (RO) │ │  │  │ REPLICA (RO) │  │
    │  └──────────────┘   │  │  └─────────────┘ │  │  └─────────────┘  │
    │                      │  │                   │  │                    │
    │  ┌──────────────┐   │  │  ┌─────────────┐ │  │  ┌─────────────┐  │
    │  │ Redis PRIMARY │◄─┼──┼─►│ Redis REPLICA│ │  │  │ Redis REPLICA│  │
    │  └──────────────┘   │  │  └─────────────┘ │  │  └─────────────┘  │
    │                      │  │                   │  │                    │
    │  ┌──────────────┐   │  │  ┌─────────────┐ │  │  ┌─────────────┐  │
    │  │ Temporal      │◄─┼──┼─►│ Temporal     │ │  │  │ Temporal     │  │
    │  │ (Primary)     │   │  │  │ (Standby)   │ │  │  │ (Standby)   │  │
    │  └──────────────┘   │  │  └─────────────┘ │  │  └─────────────┘  │
    └──────────────────────┘  └──────────────────┘  └────────────────────┘
```

## PostgreSQL Primary-Replica Setup

### Primary Region (us-east-1)

```yaml
# PostgreSQL primary with streaming replication
postgresql:
  primary:
    configuration:
      wal_level: replica
      max_wal_senders: 10
      max_replication_slots: 10
      synchronous_standby_names: ''
      hot_standby: on
      archive_mode: on
      archive_command: 'aws s3 cp %p s3://zovarc-wal-archive/%f'
```

### Replica Regions

```yaml
# PostgreSQL read replica (EU/APAC)
postgresql:
  replica:
    primary_conninfo: 'host=pg-primary.us-east-1 port=5432 user=replicator password=<secret>'
    primary_slot_name: 'replica_eu_west_1'
    recovery_target_timeline: latest
    hot_standby: on
```

### Failover

1. Promote replica to primary: `pg_ctl promote`
2. Update DNS to point to new primary
3. Reconfigure remaining replicas to follow new primary
4. Update application DATABASE_URL

## Redis Cluster Configuration

### Primary (us-east-1)

```yaml
redis:
  cluster:
    enabled: true
    replicas: 1
  sentinel:
    enabled: true
    masterSet: zovarc-master
    replicas: 3
```

### Cross-Region Replication

```yaml
# Redis secondary regions use SLAVEOF
redis:
  replicaOf:
    host: redis-primary.us-east-1
    port: 6379
  readOnly: true
```

## Temporal Multi-Cluster

Temporal supports multi-cluster replication for cross-region workflow execution.

### Configuration

```yaml
# Primary cluster
temporal:
  clusterMetadata:
    currentClusterName: us-east-1
    clusterInformation:
      us-east-1:
        enabled: true
        initialFailoverVersion: 1
        rpcAddress: temporal.us-east-1:7233
      eu-west-1:
        enabled: true
        initialFailoverVersion: 2
        rpcAddress: temporal.eu-west-1:7233
      ap-southeast-1:
        enabled: true
        initialFailoverVersion: 3
        rpcAddress: temporal.ap-southeast-1:7233
```

### Namespace Replication

```bash
# Register namespace with replication
tctl namespace register \
  --global_domain true \
  --clusters us-east-1 eu-west-1 ap-southeast-1 \
  --active_cluster us-east-1 \
  zovarc-tasks
```

## DNS-Based Routing

### AWS Route 53 Configuration

```json
{
  "Name": "zovarc.example.com",
  "Type": "A",
  "SetIdentifier": "us-east-1",
  "Region": "us-east-1",
  "AliasTarget": {
    "DNSName": "alb-us-east-1.amazonaws.com",
    "HostedZoneId": "Z1234567890",
    "EvaluateTargetHealth": true
  }
}
```

### Health Check Policy

- Health check interval: 10 seconds
- Failure threshold: 3
- Health check path: `/health`
- Automatic failover on health check failure

## Data Sovereignty

For tenants requiring data residency:

1. **Tenant-to-Region Mapping**: Store in tenant settings which region holds their data
2. **Write Routing**: API gateway routes writes to the tenant's designated region
3. **Read Routing**: Serve reads from nearest replica that contains tenant data
4. **Migration**: Tools to move tenant data between regions on request

## Deployment Procedure

1. Deploy to primary region first
2. Verify health checks pass
3. Deploy to secondary regions
4. Verify cross-region replication
5. Update DNS weights

## Monitoring

- Per-region latency dashboards
- Replication lag alerts (PostgreSQL, Redis)
- Cross-region health check status
- Temporal workflow distribution by region
