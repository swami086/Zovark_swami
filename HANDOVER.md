# ZOVARK — AI-to-AI Handover Guide

> Read this BEFORE writing any code. Violations of these rules produce invalid results.

## 1. What This Project Is

Zovark is an autonomous SOC (Security Operations Center) agent. It receives SIEM alerts, investigates them through a 6-stage pipeline, and produces structured verdicts.

**The pipeline is the product. Individual tools mean nothing in isolation.**

```
Alert → API (:8090) → Temporal → Ingest → Analyze → Execute → Assess → Govern → Store → Verdict
```

Each stage transforms data. Skipping stages produces wrong results.

## 2. Rules of Engagement (MANDATORY)

### Testing

- **ALWAYS test through the API** (`POST /api/v1/tasks`), never by calling Python functions directly
- Individual tools (e.g., `detect_ransomware()`) are internal implementation details. They are selected and orchestrated by investigation plans. Calling them directly tests nothing meaningful.
- The correct test flow:
  1. Login: `POST /api/v1/auth/login` → get JWT token
  2. Submit: `POST /api/v1/tasks` with task_type + siem_event
  3. Wait 60-90 seconds
  4. Poll: `GET /api/v1/tasks/{id}` → check verdict, risk_score, tools_executed
- Unit tests go in `worker/tests/test_*.py` and are run inside the worker container: `docker compose exec -T worker python -m pytest tests/ -q`
- Rate limit: 10 auth attempts per 15 minutes per IP. Use ONE login per test batch.

### Code Changes

- **Never create files in the repo root** (no `debug_*.py`, no `test_*.py` in root)
- Scripts go in `scripts/`, tests go in `worker/tests/`
- After Python changes: `docker compose build worker && docker compose up -d worker`
- After Go changes: `docker compose build api && docker compose up -d api`
- Do not leave debug/scratch files in the repo

### Architecture Constraints

- **Task types map to investigation plans** via `worker/tools/investigation_plans.json`. The key names in that file are the canonical names (e.g., `phishing_investigation`, not `phishing`). The analyze stage resolves aliases.
- **Tools are chained in plans**, not called individually. A brute force investigation runs: `parse_auth_log → extract_ipv4 → extract_usernames → count_pattern → score_brute_force → correlate_with_history → map_mitre`. Testing just `score_brute_force` in isolation is meaningless.
- **The assess stage transforms everything.** Even if a tool returns risk=50, the assess stage applies signal boost, risk floor, suppression detection, IOC provenance validation, and verdict derivation. The final verdict comes from assess, not from tools.
- **Benign routing is inverted logic.** Alerts route to benign by default UNLESS they match attack indicators. This is intentional. Don't "fix" benign routing without understanding `ATTACK_INDICATORS` in `ingest.py`.

### What NOT to Do

- Do NOT call detection tools directly and report "detection rate" — this bypasses plan orchestration, assess-stage scoring, and signal boost. The number will be wrong.
- Do NOT create arbitrary tool-to-attack mappings. The real mappings are in `investigation_plans.json`.
- Do NOT import from `/app/` paths in scripts that run outside Docker.
- Do NOT commit simulation results as ground truth. Simulation methodology must be validated first.
- Do NOT modify `assess.py` signal boost patterns, risk floors, or verdict logic without running the full test suite AND a 5-alert smoke test through the API.

## 3. Quick Reference

| Item | Location |
|------|----------|
| Full architecture | `CLAUDE.md` (canonical, 800+ lines) |
| Tool catalog | `worker/tools/catalog.py` |
| Investigation plans | `worker/tools/investigation_plans.json` |
| Detection tools | `worker/tools/detection.py` |
| Pipeline stages | `worker/stages/{ingest,analyze,execute,assess,govern,store}.py` |
| Tests | `worker/tests/test_*.py` (run inside container) |
| State tracking | `state/system.json`, `state/tools.json`, `state/memory.md` |
| Scoreboard | `autoresearch/SCOREBOARD.md` |

## 4. How to Run a Valid Smoke Test

```bash
# 1. Check health
curl -s http://localhost:8090/ready

# 2. Login (ONCE — save the token)
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# 3. Submit an attack alert
curl -s -X POST http://localhost:8090/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"brute_force","input":{"prompt":"SSH brute force","severity":"high","siem_event":{"title":"SSH BF","source_ip":"185.220.101.45","username":"root","rule_name":"BruteForce","raw_log":"500 failed login attempts for root from 185.220.101.45 in 60 seconds via sshd"}}}'

# 4. Wait 60-90 seconds, then poll
curl -s http://localhost:8090/api/v1/tasks/{TASK_ID} -H "Authorization: Bearer $TOKEN"

# 5. Verify: status=completed, verdict=true_positive, risk_score>=70
```

**Expected results for common alert types:**

| task_type | Expected Verdict | Expected Risk |
|-----------|-----------------|---------------|
| brute_force | true_positive | 70-100 |
| phishing | true_positive | 70-100 |
| ransomware | true_positive | 80-100 |
| password_change | benign | 0-15 |
| windows_update | benign | 0-15 |

## 5. How to Run Unit Tests

```bash
# All tests (inside worker container)
docker compose exec -T worker python -m pytest tests/ -q --tb=short

# Specific test file
docker compose exec -T worker python -m pytest tests/test_detection_cycle7.py -q

# Known pre-existing failures (skip these):
# - test_egress_controller.py::test_external_without_proxy_returns_empty (env-dependent)
# - test_adversarial_review.py::TestReviewFailSafe (3 tests, documented known issue)
```

## 6. Current Metrics (update after changes)

| Metric | Value |
|--------|-------|
| Tools | 39 |
| Investigation plans | 24 |
| Red team vectors | 40 |
| Tests passing | 370+ (excluding known failures) |
| Detection rate (API-tested) | 100% on 5-alert smoke test |

## 7. After Making Changes

1. Run unit tests: `docker compose exec -T worker python -m pytest tests/ -q`
2. Run 5-alert smoke test through the API (see section 4)
3. Update `state/system.json` metrics
4. Update `state/memory.md` with what changed and why
5. Update `autoresearch/SCOREBOARD.md` if doing AutoResearch cycles
6. Commit with descriptive message
7. Verify `git status` is clean (no debug files left behind)

## 8. Common Mistakes and How to Avoid Them

| Mistake | Why It's Wrong | What to Do Instead |
|---------|---------------|-------------------|
| Calling `detect_phishing()` directly | Bypasses plan orchestration and assess scoring | Submit via API with `task_type=phishing` |
| Reporting "26% detection rate" from direct tool calls | Tools aren't designed to be called standalone | Test through the full pipeline via API |
| Creating `debug_*.py` in repo root | Pollutes the repo, won't run outside Docker anyway | Use `scripts/` dir, clean up when done |
| Mapping `privilege_escalation → detect_com_hijacking` | Arbitrary; real mapping is in investigation_plans.json | Read `investigation_plans.json` for actual tool chains |
| Running 100 tests with 100 logins | Triggers rate limiter (10/15min) | Login once, reuse token for all requests |
