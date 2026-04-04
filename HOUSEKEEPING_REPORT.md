# Codebase Housekeeping Report — v3.2.1

Generated: 2026-04-04
Branch: v3.1-hardening

---

## 1. Ollama Remnants

### FALLBACK — Functional but Ollama-specific (REMOVE)

| File | Line(s) | What | Action |
|------|---------|------|--------|
| `agent/healer.py` | 377 | `check_http(f"{LLM_HOST}/api/tags")` — inference health check uses Ollama API | Replace with `/health` (llama-server standard) |
| `agent/healer.py` | 542 | `f"{LLM_HOST}/api/generate"` — AI crash diagnosis uses Ollama generate API | Replace with `/v1/chat/completions` |
| `agent/healer.py` | 701 | `f"{LLM_HOST}/api/tags"` — connectivity check uses Ollama API | Replace with `/health` |
| `api/handlers.go` | 40-46 | `/api/tags` fallback in `healthCheckHandler` after `/health` fails | Remove fallback block |
| `worker/stages/llm_gateway.py` | 243-260 | `preload_llm_models()` uses `/api/generate` (Ollama-only endpoint). `preload_ollama_model` backward compat alias. | Remove function or rewrite for llama-server `/health` |
| `docker-compose.yml` | 211-228 | Entire deprecated `ollama` service definition (profile: airgap-ollama) | Remove service block |
| `docker-compose.yml` | 289 | `ZOVARK_MODEL_FAST` default is `llama3.2:3b` (Ollama tag format) | Change to `nemotron-mini-4b` |
| `docker-compose.yml` | 290 | `ZOVARK_MODEL_CODE` default is `llama3.1:8b` (Ollama tag format) | Change to `nemotron-mini-4b` |
| `docker-compose.yml` | 304 | `host.docker.internal` in worker NO_PROXY list | Remove from NO_PROXY |
| `docker-compose.yml` | 614 | `ZOVARK_LLM_FAST_MODEL` default `llama3.2:3b` for healer | Change to `nemotron-mini-4b` |
| `docker-compose.yml` | 615 | `ZOVARK_LLM_BASE_URL` default `http://host.docker.internal:11434` for healer | Change to `http://zovark-inference:8080` |
| `docker-compose.yml` | 620 | `extra_hosts: host.docker.internal:host-gateway` for healer | Remove (healer on same docker network) |
| `docker-compose.yml` | 768 | `ollama_data:` named volume | Remove |
| `cmd/zvadmin/update.go` | 413-429 | `restartHostLLM()` — tries zovark-inference first (correct), no Ollama fallback. Clean. | OK — no action needed |

### DEAD — In stale/unused files (DELETE or ARCHIVE)

| File | Line(s) | What |
|------|---------|------|
| `docker-compose.test.yml` | 1-28 | Entire `mock-ollama` container on port 11434 (CI test fixture) |
| `docker-compose.airgap.yml` | 65-68 | Ollama service definition |
| `.github/workflows/ci.yml` | 188 | `curl -sf http://localhost:11434/health` |
| `.github/workflows/ci.yml` | 241 | `logs --tail=50 mock-ollama` |
| `tests/test_path_b_direct.py` | 1-325 | Entire file: `OLLAMA_URL`, `call_ollama()`, `host.docker.internal:11434` |
| `scripts/airgap-setup.sh` | 1-33 | Entire file: pulls models via `docker compose exec ollama ollama pull` |
| `scripts/export_airgap.sh` | 36-52 | References `ollama/ollama:latest`, exports ollama model weights |
| `scripts/benchmark_via_api.py` | 9 | Default URL `http://localhost:11434/v1/chat/completions` |
| `dpo/batch_generate.py` | 10-78 | `OLLAMA_URL` variable, `host.docker.internal:11434` |
| `deploy/scripts/health-check.sh` | 64-65 | `host.docker.internal:11434` fallback |
| `LICENSES/MODELS/ATTRIBUTION.md` | 4 | "All models run on-premise via Ollama" |
| `autoresearch/redteam/validate_bypasses.py` | 23 | `OLLAMA_ENDPOINT` variable name |
| `autoresearch/continuous/telemetry_reader.py` | 222-237 | Section header "SOURCE 4: OLLAMA", checks for `llama3.1:8b`, `llama3.2:3b` |

### DEAD — In docs (low priority, historical context)

| File | What |
|------|------|
| `ZOVARK_Research_Prompt.md` | 6 references — historical architecture decisions |
| `ZOVARK_NOTEBOOK.md` | "Ollama" in stack description |
| `VALIDATION_REPORT.md` | "Ollama air-gap fallback available" |
| `docs/ARCHITECTURE.md` | Lines 628, 1133, 1167 — keep_alive explanation, airgap-ollama profile, mock_ollama test |
| `docs/DEPLOYMENT_GUIDE.md` | Multiple 11434 references throughout |
| `docs/WHITEPAPER.md` | Lines 98, 110, 173 — "via Ollama", port 11434 |
| `docs/HARDWARE_REQUIREMENTS.md` | Lines 10, 13, 68, 70 — "Ollama", port 11434 |
| `docs/MODEL_DEPLOYMENT.md` | Lines 5, 58, 61, 83, 107 — "Ollama", 11434 throughout |
| `docs/FAILURE_MODES.md` | Lines 11, 39-40 — Ollama fallback flow |
| `docs/PROJECT_STATUS.md` | Lines 31, 59-60 — "Ollama: Healthy" |
| `docs/DEMO_SCRIPT.md` | Line 6 — `curl http://localhost:11434/v1/models` |
| `docs/SCALING.md` | Line 205 — "Ollama" |
| `docs/JUICE_SHOP_BENCHMARK.md` | Line 70 — "via Ollama" |
| `docs/ZOVARK_IMPLEMENTATION_AUDIT.md` | Lines 239, 242, 294 — Ollama runtime |
| `marketing/outreach/ciso_brief.md` | Line 61 — "local Ollama endpoint" |
| `marketing/conference/CONFERENCE_SUBMISSIONS.md` | Lines 28, 40 — Ollama references |
| `k8s/README.md` | Line 112 — "Local Ollama" |
| `files/ZOVARK_Complete_Architecture_Strategy_Sprints.md` | Lines 214, 363 — "Ollama/vLLM" |
| `docs/archive/*` | Multiple files — historical (leave in archive) |

### FALSE POSITIVE — Intentional meta-references

| File | Why |
|------|-----|
| `CLAUDE.md` | Documents Ollama de-coupling history and mock-ollama CI note |
| `HANDOVER.md` | Instructs "No Ollama. No port 11434." (prescriptive) |

---

## 2. Stale Function Names

**No matches found for `call_slow`, `call_fast_model`, or `call_code_model`.** All LLM calls use canonical `call_fast()` / `call_code()` pattern (via `llm_gateway.llm_call()` with model routing).

---

## 3. v2-Only Files Without Demarcation

| File | Why v2-only | Has demarcation? |
|------|-------------|-----------------|
| `worker/_legacy_activities.py` | Entire file is v2 sandbox pipeline activities. Contains `should_retry`, `generate_retry_hints`, Docker sandbox execution. | **NO** |

**Files with proper v2/v3 branching (no demarcation needed — they serve both modes):**
- `worker/stages/analyze.py` — `EXECUTION_MODE` check at line 504
- `worker/stages/execute.py` — `EXECUTION_MODE` check at line 270
- `worker/stages/assess.py` — `execution_mode` param in `_derive_verdict()` at line 38
- `worker/stages/__init__.py` — dataclass default `execution_mode: str = "sandbox"`
- `worker/tools/tests/test_path_d.py` — tests both modes

---

## 4. AutoResearch Directory Audit

### ACTIVE (keep as-is)

| Directory | Status | Issues |
|-----------|--------|--------|
| `cycle10/` | ACTIVE — current regression + dedup stress tests | None |
| `telemetry_driven/` | ACTIVE — telemetry-driven AutoResearch engine | None |
| `redteam_nightly/` | ACTIVE — nightly red team attack vectors | None |

### ACTIVE but with outdated references

| Directory | Status | Outdated References |
|-----------|--------|-------------------|
| `assess_prompt/` | ACTIVE | `evaluate.py:21` and `evaluate_full.py:21`: `MODEL = "llama3.1:8b"` → should be `"nemotron-mini-4b"` |
| `tool_selection_prompt/` | ACTIVE | `evaluate.py:16` and `evaluate_full.py:16`: `MODEL = "llama3.2:3b"` → should be `"nemotron-mini-4b"` |
| `redteam/` | ACTIVE | `validate_bypasses.py:23-26`: `OLLAMA_ENDPOINT` variable, default `"llama3.1:8b"` |
| `continuous/` | ACTIVE | `telemetry_reader.py:222-237`: Section header "SOURCE 4: OLLAMA", checks for `llama3.1:8b`, `llama3.2:3b` |

### ARCHIVE CANDIDATES

| Directory | Last Activity | Reason |
|-----------|--------------|--------|
| `cycle9/` | 2026-04-03 | Completed validation cycle. Superseded by cycle10. |
| `templates/` | 2026-03-31 | Template engineering program completed (10/10 approved). |
| `tool_hardening/` | 2026-04-02 | Tool hardening completed (11/12 tools). |
| `tools/` | 2026-03-31 | Initial tool evaluation framework. Superseded by tool_hardening. |
| `tools_redteam/` | 2026-03-31 | v3 tool-calling red team tests. Completed. |

---

## 5. Stale Comments (TODO / HACK / FIXME)

| File | Line | Comment | Status |
|------|------|---------|--------|
| `api/siem.go` | 76 | `TODO(security): Go-side sanitization is limited to control-char stripping and...` | STILL RELEVANT — Python sanitizer is primary, Go-side is minimal |
| `worker/rate_limiter.py` | 129 | `TODO: For >100 concurrent tasks per tenant, migrate from SET to sorted sets` | STILL RELEVANT — scale optimization |
| `scripts/seed_templates.py` | 475 | `TODO: Implement full detection` | DEAD — detection tools are now implemented in `worker/tools/detection.py` |
| `scripts/seed_skills.py` | 462 | `TODO: Implement specific detection engine logic here` | DEAD — detection tools are now implemented |
| `dpo/generate_rejected.py` | 24-25 | `# TODO: extract IOCs` / `# TODO: extract patterns` | FALSE POSITIVE — these are intentionally bad code in DPO rejected samples |
| `dpo/assemble_dataset.py` | 67 | `if "TODO" in rejected` | FALSE POSITIVE — checking for TODO in generated DPO data |
| `dpo/prompts_v2.py` | 12 | `Manus todo.md pattern` | FALSE POSITIVE — describes a prompt engineering technique |

---

## 6. Dead Imports

| File | Line | Unused Import |
|------|------|---------------|
| `worker/stages/ingest.py` | 12 | `time` |
| `worker/stages/analyze.py` | 28 | `Optional`, `Dict` (from typing) |
| `worker/stages/execute.py` | 17 | `List` (from typing) |
| `worker/stages/assess.py` | 15 | `List`, `Dict` (from typing) |
| `worker/stages/assess.py` | 18 | `httpx` |
| `worker/stages/store.py` | 10 | `time` |
| `worker/stages/llm_gateway.py` | 13 | `ZOVARK_LLM_ENDPOINT` (line 13, shadowed by `_DEFAULT_ENDPOINT` on line 29) |
| `worker/settings.py` | 6 | `os` |
| `worker/tools/detection.py` | 3 | `json` |
| `worker/tools/detection.py` | 4 | `math` |
| `worker/tools/detection.py` | 5 | `Counter` (from collections) |
| `worker/tools/detection.py` | 8 | `parse_auth_log` (from tools.parsing) |
| `worker/tools/detection.py` | 9 | `score_brute_force`, `score_phishing`, `score_c2_beacon`, `score_exfiltration`, `score_generic` (from tools.scoring) |
| `worker/tools/detection.py` | 10 | `count_pattern` (from tools.analysis) |
| `worker/_legacy_activities.py` | 27 | `should_retry`, `generate_retry_hints` (from dpo.prompts_v2) |

**Total: 28 dead imports across 9 files.**
Worst offender: `worker/tools/detection.py` — 10 unused imports from scoring/parsing/analysis modules.

---

## 7. Stale Model Defaults in docker-compose.yml

These are not strictly "Ollama" but use Ollama's tag format (`model:version`) instead of the current model alias:

| File | Line | Current Default | Should Be |
|------|------|----------------|-----------|
| `docker-compose.yml` | 289 | `ZOVARK_MODEL_FAST:-llama3.2:3b` | `nemotron-mini-4b` |
| `docker-compose.yml` | 290 | `ZOVARK_MODEL_CODE:-llama3.1:8b` | `nemotron-mini-4b` |
| `docker-compose.yml` | 614 | `ZOVARK_LLM_FAST_MODEL:-llama3.2:3b` | `nemotron-mini-4b` |

---

## Summary

| Category | Count | Severity |
|----------|-------|----------|
| Ollama remnants in active code (FALLBACK) | 14 hits in 4 files | HIGH — causes confusion, stale fallbacks |
| Ollama remnants in dead/stale files | 13 hits in 13 files | MEDIUM — cleanup targets |
| Ollama remnants in docs | 20+ hits in 18 files | LOW — historical context |
| Stale function names | 0 | CLEAN |
| v2-only files without demarcation | 1 file | LOW |
| AutoResearch outdated model refs | 6 files in 4 directories | MEDIUM |
| Stale TODOs (dead) | 2 | LOW |
| Dead Python imports | 28 across 9 files | LOW |
| Stale model defaults in compose | 3 | HIGH — affects runtime |
