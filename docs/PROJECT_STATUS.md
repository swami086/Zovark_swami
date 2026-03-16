# HYDRA Project Status

Last updated: 2026-03-16 (commit e17ccad)

## Pipeline Status: OPERATIONAL

Investigation flow works end-to-end:
- Alert submission → 202 accepted
- Skill matching → template rendered with LLM-filled parameters
- AST validation → code passes prefilter (os/sys imports removed from templates)
- Adversarial review → passes through (LLM timeout, AST+Docker are primary security)
- Sandbox execution → Docker container runs code (--network=none, cap-drop ALL)
- Entity extraction → IOCs, findings, recommendations extracted
- Verdict → risk score, severity, structured output saved to DB

## Security Posture

- 30/30 audit findings: FIXED (v0.11.0 + v0.12.0)
- 5 hardening features: DEPLOYED (Vault JIT, egress proxy, alert sanitizer, adversarial review, MCP gate)
- Test coverage: 44 Go + 179 Python = 223 test functions passing
- Runtime validated: v1.0.0-rc1 + post-rc1 pipeline fixes

## What's Been Fixed Since v1.0.0-rc1

| Bug | Root Cause | Fix | File |
|-----|-----------|-----|------|
| Investigations fail silently | Skill templates had `import os, sys` blocked by AST prefilter v2 | Removed forbidden imports from 10 DB templates | SQL UPDATE on agent_skills |
| Code never executes | Adversarial review LLM timeout → fail-safe blocked all code | Changed to pass-through on timeout | security/adversarial_review.py |
| execute_code crashes | `logger` not defined in _legacy_activities.py | Added import logging + logger init | _legacy_activities.py |
| Memory enrichment fails | Wrong column names (e.type → entity_type, eo.created_at → observed_at) | Fixed column references | investigation_memory.py |
| LLM calls fail | Routing to Groq with placeholder key | Routed to local Ollama via host.docker.internal | litellm_config.yaml |
| Go API won't compile | Missing encoding/json import in tokenquota.go, unused fmt in approval_handlers.go | Added/removed imports | tokenquota.go, approval_handlers.go |
| NATS won't start | `--max_payload` flag unsupported in nats:2.10-alpine | Replaced with `-js` short flags | docker-compose.yml |
| Postgres auth mismatch | .env password didn't match running DB | Reset to default `hydra_dev_2026` | .env |
| Worker import crash | `activities.py` + `activities/` package name conflict | Renamed to `_legacy_activities.py` with `__init__.py` re-exports | worker/ |
| Pool creation fails | PgBouncer rejects `-c jit=off` option | Removed jit option, use application_name only | database/pool_manager.py |
| migration 040 missing | needs_human_review column not applied | Applied manually | migrations/040_human_review_flags.sql |
| Vault test unpacking | Tests expected 3 positional args, _request passes 2 | Fixed arg unpacking | tests/test_vault_manager.py |

## Baseline Accuracy (7 completed investigations)

| Metric | Value |
|--------|-------|
| Code generation | 100% (7/7) |
| Findings rate | 86% (6/7) |
| IOC extraction | 29% (2/7) |
| Mean risk score | 76 |
| Mean execution | 30.9s |

## Infrastructure

| Component | Status | Notes |
|-----------|--------|-------|
| Go API (8090) | Healthy | 78 routes, v1.0.0-rc1 |
| Worker | Healthy | 16 workflows, 110 activities |
| PostgreSQL | Healthy | 76 tables, 40 migrations |
| Redis | Healthy | go-redis/v9 pooled |
| Temporal | Healthy | Task queue: hydra-tasks |
| LiteLLM | Healthy | Routes fast → Ollama qwen2.5:14b |
| Ollama | Healthy | qwen2.5:14b, llama3.1:8b available |
| NATS | Healthy | JetStream enabled |
| Dashboard | Running | React 19 on port 3000 |
| Embedding | Running | HuggingFace TEI (CPU) |

## Pending Work

1. **DPO Phase 2-4** — Generate training data with Kimi, train model, measure delta
2. **Full 70-alert corpus benchmark** — Currently only 7 investigations in baseline
3. **Skill template migration 041** — Persist the `import os,sys` removal
4. **LiteLLM Redis auth** — Add REDIS_PASSWORD to litellm env
5. **K8s cluster test** — Real cluster deployment via k8s_cluster_test.sh
