# HYDRA v1.0.0-rc1 — Release Candidate

## What's New Since v0.10.0

- **30/30 security audit findings resolved** (v0.10.1 → v0.11.0)
- **5 defense-in-depth hardening features** (Vault JIT, egress proxy, alert sanitization, adversarial review, MCP approval gate)
- **10 platform features** (ML detection, network analysis, real-time collaboration, CISA KEV processing)
- **5 architectural fixes** (CI gates, DB pooling, go-redis, handler split, workflow registration)
- **130+ automated tests** (Go unit + Python pytest + E2E integration)
- **Migration runner** (golang-migrate with advisory lock, up/down/version/force)
- **CI/CD pipeline** with real failure gates (no `|| true`)
- **48-hour PoV package** for customer evaluation (SIEM import, report generation, deploy script)
- **Analyst feedback loop** (FP detection, rule accuracy tracking, daily aggregation)
- **Playbook template resolution** (14 variables, injection-safe)

## Architecture at rc1

| Layer | Technology | Status |
|-------|-----------|--------|
| API Gateway | Go + Gin (65+ endpoints) | Production-ready |
| Worker | Python + Temporal (16 workflows, 104 activities) | Production-ready |
| Database | PostgreSQL 16 + pgvector (39 migrations) | Production-ready |
| Cache | Redis 7 via go-redis/v9 (pooled) | Production-ready |
| Orchestration | Temporal 1.24.2 | Production-ready |
| Messaging | NATS JetStream | Production-ready |
| Sandbox | Docker + seccomp + AST v2 + kill timer | Production-ready |
| Dashboard | React 19 + Vite 7 + Tailwind 4 | Production-ready |
| Monitoring | Prometheus + Grafana (3 dashboards) | Production-ready |
| LLM | Multi-provider fallback (5 chains) | Production-ready |
| K8s | Kustomize + HPA + KEDA (3 overlays) | Validated (dry-run) |

## Known Limitations

- DeepLog model requires training data (architecture ready, model weights TODO)
- StringSifter classifier requires training data (pipeline ready, model weights TODO)
- K8s manifests validated via dry-run but not cluster-tested
- Single Qwen 1.5B model for local inference (VRAM constraint on RTX 3050)

## Deployment

- **Quick PoV:** `bash scripts/pov/deploy.sh`
- **Production:** See `docs/DEPLOYMENT_GUIDE.md`
- **Kubernetes:** See `k8s/` with `kubectl apply -k k8s/overlays/production/`

## What's NOT in rc1 (Planned for v1.0.0 GA)

- External penetration test
- SOC2 Type I documentation
- Pilot customer onboarding runbook
- Production K8s cluster testing
- DeepLog/StringSifter model training
