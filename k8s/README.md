# ZOVARC Kubernetes Deployment

## Quick Start (Dev)

```bash
# Create secrets first
cp k8s/base/secrets.yaml.example k8s/base/secrets.yaml
# Edit k8s/base/secrets.yaml with real values

kubectl apply -f k8s/base/secrets.yaml
kubectl apply -k k8s/overlays/dev
```

## Production Deployment

```bash
# 1. Create namespace
kubectl apply -f k8s/base/namespace.yaml

# 2. Create secrets (from your secret management system)
kubectl apply -f k8s/base/secrets.yaml

# 3. Deploy with production overlay
kubectl apply -k k8s/overlays/production

# 4. Verify
kubectl -n zovarc get pods
kubectl -n zovarc get hpa
kubectl -n zovarc get networkpolicy
```

## Air-Gap Deployment

```bash
# 1. Push images to internal registry
for img in pgvector:pg16 pgbouncer:latest redis:7-alpine temporal-auto-setup:1.24.2 litellm-database:main-stable; do
  docker tag <source>/$img internal-registry.local:5000/zovarc/$img
  docker push internal-registry.local:5000/zovarc/$img
done

# 2. Build and push ZOVARC images
docker build -t internal-registry.local:5000/zovarc/worker:latest ./worker
docker build -t internal-registry.local:5000/zovarc/api:latest ./api
docker build -t internal-registry.local:5000/zovarc/dashboard:latest ./dashboard
docker push internal-registry.local:5000/zovarc/{worker,api,dashboard}:latest

# 3. Deploy
kubectl apply -k k8s/overlays/airgap
```

## Scaling

### Automatic (HPA)

Worker and API pods scale automatically based on CPU utilization (target: 70%).

| Component | Min | Max | Scale Up    | Scale Down    |
|-----------|-----|-----|-------------|---------------|
| Worker    | 2   | 50  | +4 pods/60s | -2 pods/120s  |
| API       | 2   | 10  | +2 pods/60s | -1 pod/60s    |

### Manual Override

```bash
# Scale workers manually
kubectl -n zovarc scale deployment zovarc-worker --replicas=8

# Check current replicas
kubectl -n zovarc get hpa
```

## Security Verification

```bash
# Verify NetworkPolicy is applied
kubectl -n zovarc get networkpolicy
kubectl -n zovarc describe networkpolicy zovarc-worker-netpol

# Test worker isolation (should fail — workers accept no inbound)
kubectl -n zovarc exec deploy/zovarc-api -- curl -s http://zovarc-worker:8080 || echo "Correctly blocked"

# Verify worker can only reach allowed services
kubectl -n zovarc exec deploy/zovarc-worker -- curl -s http://litellm:4000/health/liveliness  # Should succeed
kubectl -n zovarc exec deploy/zovarc-worker -- curl -s http://zovarc-dashboard:3000  # Should fail
```

## Monitoring

```bash
# Pod status
kubectl -n zovarc get pods -o wide

# HPA status
kubectl -n zovarc get hpa

# Worker logs
kubectl -n zovarc logs -l component=worker --tail=50 -f

# Resource usage
kubectl -n zovarc top pods
```

## Overlay Comparison

| Setting          | Dev    | Production | Air-Gap    |
|------------------|--------|------------|------------|
| Worker replicas  | 1      | 4          | 2 (base)   |
| Worker HPA max   | 4      | 50         | 50 (base)  |
| API replicas     | 1      | 2          | 2 (base)   |
| Postgres memory  | 512Mi  | 4Gi        | 2Gi (base) |
| Image registry   | local  | local      | internal-registry.local:5000 |
| LLM backend      | OpenRouter | OpenRouter | Local Ollama |
