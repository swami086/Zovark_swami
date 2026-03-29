# HYDRA Codebase Architecture Audit — Full Dump for External Collaborator

## PURPOSE

Read the entire HYDRA codebase and produce a comprehensive architecture document that an external AI collaborator (Brainiac) can use to understand every file, table, endpoint, workflow, and convention without access to the repo. This is a ONE-TIME knowledge transfer document.

## INSTRUCTIONS

Execute every step below. Do NOT skip any section. Output everything to a single file: `docs/HYDRA_CODEBASE_ARCHITECTURE.md`

---

## STEP 1: Repository Structure

```bash
# Full directory tree (2 levels deep, skip node_modules and dist)
find . -maxdepth 3 -type f | grep -v node_modules | grep -v dist | grep -v .git | grep -v __pycache__ | sort
```

Record the complete file listing in the output document.

## STEP 2: Git History Summary

```bash
git log --oneline --all | head -40
git shortlog -sn
```

## STEP 3: Docker Compose — Full Service Map

```bash
cat docker-compose.yml
```

For each service, document: image, ports, volumes, environment variables, dependencies.

## STEP 4: Database Schema — Complete

```bash
docker compose exec -T postgres psql -U hydra -d hydra -c "\dt+" 
docker compose exec -T postgres psql -U hydra -d hydra -c "\dm+"
docker compose exec -T postgres psql -U hydra -d hydra -c "\dv+"
```

Then for EVERY table, run:
```bash
docker compose exec -T postgres psql -U hydra -d hydra -c "\d {table_name}"
```

Also get row counts:
```bash
docker compose exec -T postgres psql -U hydra -d hydra -c "
SELECT schemaname, relname, n_live_tup 
FROM pg_stat_user_tables 
ORDER BY n_live_tup DESC"
```

And list all indexes:
```bash
docker compose exec -T postgres psql -U hydra -d hydra -c "
SELECT tablename, indexname, indexdef 
FROM pg_indexes 
WHERE schemaname = 'public' 
ORDER BY tablename"
```

## STEP 5: Go API — Full Endpoint Map

```bash
# Every route registered
grep -rn "HandleFunc\|GET\|POST\|PUT\|DELETE\|router\.\|group\." api/*.go | sort

# All handler functions
grep -rn "func.*Handler\|func.*handler" api/*.go

# Auth middleware
grep -rn "middleware\|auth\|jwt\|rbac" api/*.go
```

Read every .go file in api/ and document:
- Every endpoint (method, path, handler function, auth requirement)
- Request/response schemas (from the handler code)
- Middleware chain

## STEP 6: Python Worker — Complete Activity & Workflow Map

```bash
# All workflow classes
docker compose exec -T worker grep -rn "class.*Workflow" /app/*.py /app/**/*.py 2>/dev/null

# All activity definitions  
docker compose exec -T worker grep -rn "@activity.defn" /app/*.py /app/**/*.py 2>/dev/null

# All imports in main.py (shows what's registered)
cat worker/main.py
```

For each Python file in worker/, document:
- Purpose (from docstring or first comment)
- Functions/classes defined
- External dependencies (imports)

Read these key files completely:
- worker/main.py
- worker/workflows.py  
- worker/activities.py
- worker/model_config.py
- worker/prompt_registry.py
- worker/llm_logger.py
- worker/investigation_memory.py
- worker/entity_graph.py
- worker/validation/dry_run.py
- worker/prompts/investigation_prompt.py

## STEP 7: LiteLLM Configuration

```bash
cat litellm_config.yaml
```

Document every model, fallback chain, and routing rule.

## STEP 8: MCP Server

```bash
cat mcp-server/src/index.ts | head -100
```

List every tool, resource, and prompt registered.

## STEP 9: Dashboard Structure

```bash
find dashboard/src -name "*.tsx" -o -name "*.ts" | sort
cat dashboard/src/App.tsx
```

List every component, page, hook, and route.

## STEP 10: Kubernetes Manifests

```bash
find k8s/ -name "*.yaml" -o -name "*.yml" | sort
```

Document overlays and key configurations.

## STEP 11: Migration History

```bash
ls -la migrations/
```

For each migration, read the first 5 lines (the comment) to document purpose.

## STEP 12: Environment Variables

```bash
cat .env.example
```

Document every environment variable and its purpose.

## STEP 13: Live Data Summary

```bash
docker compose exec -T postgres psql -U hydra -d hydra -c "
SELECT 'tenants' as tbl, count(*) FROM tenants
UNION ALL SELECT 'users', count(*) FROM users
UNION ALL SELECT 'agent_tasks', count(*) FROM agent_tasks
UNION ALL SELECT 'investigations', count(*) FROM investigations
UNION ALL SELECT 'entities', count(*) FROM entities
UNION ALL SELECT 'entity_edges', count(*) FROM entity_edges
UNION ALL SELECT 'entity_observations', count(*) FROM entity_observations
UNION ALL SELECT 'detection_rules', count(*) FROM detection_rules
UNION ALL SELECT 'response_playbooks', count(*) FROM response_playbooks
UNION ALL SELECT 'agent_skills', count(*) FROM agent_skills
UNION ALL SELECT 'mitre_techniques', count(*) FROM mitre_techniques
UNION ALL SELECT 'bootstrap_corpus', count(*) FROM bootstrap_corpus
UNION ALL SELECT 'llm_call_log', count(*) FROM llm_call_log
UNION ALL SELECT 'audit_events', count(*) FROM audit_events
UNION ALL SELECT 'self_healing_events', count(*) FROM self_healing_events
UNION ALL SELECT 'alert_fingerprints', count(*) FROM alert_fingerprints
UNION ALL SELECT 'model_registry', count(*) FROM model_registry
UNION ALL SELECT 'webhook_endpoints', count(*) FROM webhook_endpoints
ORDER BY 1"

docker compose exec -T postgres psql -U hydra -d hydra -c "
SELECT entity_type, count(*) FROM entities GROUP BY entity_type ORDER BY count(*) DESC"

docker compose exec -T postgres psql -U hydra -d hydra -c "
SELECT verdict, count(*) FROM investigations GROUP BY verdict ORDER BY count(*) DESC"

docker compose exec -T postgres psql -U hydra -d hydra -c "
SELECT status, count(*) FROM agent_tasks GROUP BY status ORDER BY count(*) DESC"
```

## STEP 14: Conventions & Patterns

Document these explicitly:
- How LLM calls are made (get_tier_config + log_llm_call + get_version pattern)
- How Temporal workflows import non-deterministic modules (workflow.unsafe.imports_passed_through)
- How migrations are applied (cat file.sql | docker exec -i hydra-postgres psql -U hydra -d hydra)
- How new activities are registered (add to main.py imports + activities list)
- Protected files list (ast_prefilter.py, seccomp_profile.json, kill_timer.py)
- Line ending enforcement (.gitattributes)
- Linting rules (flake8 --max-line-length=200 --ignore=E501,W503,E402)
- DB access from host (docker compose exec -T postgres psql -U hydra -d hydra)
- Worker access from host (docker compose exec -T worker python -c "...")
- No Python on Windows host — everything runs in Docker

## OUTPUT FORMAT

Write everything to `docs/HYDRA_CODEBASE_ARCHITECTURE.md` with these sections:

```markdown
# HYDRA Codebase Architecture — Complete Reference
## Generated: {date}

## 1. Repository Structure
## 2. Git History
## 3. Docker Services (10 containers)
## 4. Database Schema (30+ tables, every column)
## 5. Go API Endpoints (42+ endpoints, every route)
## 6. Python Worker (7 workflows, 58 activities, every file)
## 7. LLM Configuration (3 tiers, fallback chains)
## 8. MCP Server (7 tools, 6 resources, 6 prompts)
## 9. Dashboard (React components, routes)
## 10. Kubernetes Manifests
## 11. Migration History (001-016)
## 12. Environment Variables
## 13. Live Data Summary
## 14. Development Conventions
## 15. Known Issues & Gaps
```

Be exhaustive. This document will be the ONLY reference an external collaborator has. If something isn't in this document, they won't know about it.

After writing the file:
```bash
git add docs/HYDRA_CODEBASE_ARCHITECTURE.md
git commit -m "docs: comprehensive codebase architecture dump for external collaboration"
git push
```
