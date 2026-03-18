# HYDRA Research Prompt — Session Context for LLMs

> Paste this into any LLM session to give it full context on the HYDRA project state.
> Last updated: 2026-03-18, Session 7 (Path B evaluation)

## Project Overview

HYDRA is an air-gapped, on-premise AI SOC platform. It receives SIEM alerts, generates Python investigation code via LLM, executes it in a sandboxed Docker container, and delivers structured verdicts with findings, IOCs, risk scores, and recommendations.

**Stack:** Go API + Python Temporal Worker + React Dashboard + PostgreSQL/pgvector + Redis + NATS + llama.cpp

## Current State

- **Version:** post v1.0.0-rc1
- **Latest commit:** `e120cb9` (Path B retest with qwen2.5:14b)
- **Pipeline:** OPERATIONAL — investigations complete end-to-end
- **LLM:** llama.cpp server, qwen2.5-14b-instruct Q4_K_M (replaces Ollama)
- **GPU offload:** 20/49 layers on RTX 3050 4GB, rest CPU (3.3 tok/s)
- **Tests:** 44 Go + 179 Python = 223 test functions
- **Services:** 17 Docker containers (Ollama replaced by host-side llama.cpp)
- **Skills:** 11 in DB (all 11 with real templates)
- **DPO dataset:** 5 validated pairs (format verified)
- **Migrations:** 001-041

## Accuracy Metrics

### Baseline (7 investigations, pre-Session 4)

| Metric | Value |
|--------|-------|
| Code generation | 100% (7/7) |
| Mean risk score | 76 |
| Findings rate | 86% (6/7) |
| IOC extraction | 29% (2/7) |
| Mean execution | 30.9s |

### Session 4 Results (live SIEM event tests)

| Test | IOCs | Findings | Risk | Time |
|------|------|----------|------|------|
| brute_force (S4) | 1 (10.0.0.99) | 2 | 95 | 30.6s |
| lateral_movement (S4) | 5 (NTLM hash, svc_backup, Administrator, hostnames) | 8 | 95 | 30.6s |
| privilege_escalation (S5) | 11 (SeDebugPrivilege, exploit.exe, backdoor.exe, lsass.exe, jsmith, IPs) | 4 | 95 | 31.0s |
| data_exfiltration (S5) | 5 (185.220.101.45, exfil-c2.net, 10.0.0.45) | 1 | 0 | 30.6s |
| supply_chain (S6) | 9 (avsvmcloud.dll, rundll32, 20.140.0.1, MD5 hashes) | 4 | 95 | 41.3s |

**IOC extraction on SIEM events: 100% (5/5 completed had IOCs)**
**Mean IOCs per investigation: 6.0**

### Full Corpus (70 alerts, offline scoring)

| Metric | Value |
|--------|-------|
| Overall accuracy (verdict) | 100% |
| Code generation success | 100% |
| IOC F1 score | 0.000 (ground truth alerts don't use siem_event path) |
| Categories | 12 |

## Architecture Summary

```
SIEM Alert → Go API (:8090) → PostgreSQL → Temporal Workflow →
  Skill RAG (retrieve_skill) → PII Masking → fill_skill_parameters →
  render_skill_template OR generate_code (v2 PromptAssembler) →
  AST Prefilter → Adversarial Review → Docker Sandbox →
  IOC Retry Loop (if 0 IOCs) → Entity Extraction → Knowledge Graph →
  Structured Verdict
```

### Two Code Generation Paths

- **Path A (Template):** `retrieve_skill` matches task_type → `fill_skill_parameters` (LLM) → `render_skill_template` → sandbox. Used when a skill template exists.
- **Path B (Generated):** `generate_code` with PromptAssembler v2 → sandbox. Used when no skill template matches.

**Current reality:** 11 task types match skill templates (Path A). Novel task types fall through to Path B. With qwen2.5:14b via llama.cpp, Path B achieves 80% execution rate and 89% IOC extraction.

### Architecture Decision (Session 8): Replace Ollama with llama.cpp

**Why:** Ollama auto-offloads layers but provides no control. On 4GB VRAM, it loaded only 33% of the model and all inference timed out. llama.cpp with explicit `--n-gpu-layers 20` loads 41% and achieves 3.3 tok/s — slow but functional.

**What changed:**
- Worker calls llama.cpp on host via `http://host.docker.internal:11434/v1/chat/completions`
- `HYDRA_LLM_MODEL=qwen2.5:14b` (llama.cpp ignores model name, serves loaded model)
- LLM special token stripping added to both `generate_code` and `generate_followup_code`
- Ollama Docker service moved to `airgap-ollama` profile (kept as fallback)
- `scripts/start_llama_server.sh` auto-detects VRAM and sets optimal GPU layers

## Key Files

| File | Purpose |
|------|---------|
| `worker/_legacy_activities.py` | 23 core activities including generate_code, fill_skill_parameters |
| `worker/_legacy_workflows.py` | ExecuteTaskWorkflow — main investigation pipeline |
| `worker/skills/lateral_movement.py` | PtH/NTLM/mimikatz detection template |
| `worker/skills/network_beaconing.py` | C2 beacon + DNS tunnel detection template |
| `worker/skills/deobfuscation.py` | Base64/hex/PowerShell payload decoder |
| `dpo/prompts_v2.py` | 16 prompts, PromptAssembler, retry loop, specialist personas |
| `dpo/prompts.py` | v1 prompts (fallback) |
| `worker/model_config.py` | 3-tier model routing (fast/standard/reasoning) |
| `litellm_config.yaml` | LLM provider config with fallback chains |
| `scripts/accuracy_benchmark.py` | Full corpus accuracy measurement |
| `scripts/seed_templates.py` | Load skill templates into DB |

## Session History

### Session 4 (2026-03-17)

**Commits:** `73222e2`, `a45ffc8`, `72bd068`, `8ae0f25`, `9a1a821`, `7975284`, `3ec86be`, `71bf002`

**What was done:**
1. **Prompts v2 modular assembler** (`dpo/prompts_v2.py`, 865 lines)
   - 16 prompts in 8 composable blocks (system, tools, task, examples, planning, persona, retry, objective)
   - KV-cache optimized: stable blocks at top, objective recitation at bottom
   - PromptAssembler class with build_investigation_prompt() and build_retry_prompt()
   - 10 specialist personas (brute_force, malware, lateral_movement, etc.)
   - TECHNIQUE_IOC_MAP with required/optional IOC types per technique
   - IOC retry loop: should_retry() + generate_retry_hints()

2. **SIEM raw_log injection fix** (commit `a45ffc8`)
   - When `fill_skill_parameters` LLM call fails, inject `siem_event.raw_log` as `log_data`
   - Adds structured header (source_ip, dest_ip, hostname, username, rule_name)
   - Templates now analyze real alert data instead of mock data

3. **IOC retry loop wired for both paths** (commit `a45ffc8`)
   - Removed `not is_template` guard — retry applies to template output too
   - Added IOC dict flattening: `{"ips":[], "domains":[]}` → `[{"type":"ip", "value":"x"}]`
   - Retry calls generate_code (v2 path) even if original was template

4. **Network beaconing skill** (commit `72bd068`)
   - `worker/skills/network_beaconing.py`: Zeek conn.log/DNS analysis
   - Beacon jitter analysis (coefficient of variation)
   - DNS tunneling via Shannon entropy
   - Migration 041 applied

5. **LiteLLM fix** (commit `73222e2`)
   - All cloud API keys were placeholders (401 "User not found")
   - Set `HYDRA_LLM_MODEL=fast` to route all tiers through local Ollama
   - Fixes generate_code and generate_followup_code failures

6. **Lateral movement real skill template** (commit `73222e2`)
   - Replaced skeleton template with full PtH/NTLM/mimikatz detection
   - 8 detection phases: PtH, mimikatz, NTLM hash, priv esc, credential abuse, svc account abuse
   - extract_iocs() integrated for full regex IOC sweep
   - Test result: 5 IOCs, 8 findings, risk 95

7. **DPO forge fixes + 5-pair dataset** (commit `71bf002`)
   - hydra_dpo_dataset.jsonl validated (5 pairs, ChatML format, within 2048 budget)
   - smoke_test_dpo.py for zero-dependency validation

### Session 5 (2026-03-18)

**Commits:** `cddf7e1`

**What was done:**
1. **privilege_escalation real skill template** (`worker/skills/privilege_escalation.py`)
   - Token theft (EventID 4672, SeDebugPrivilege, SeTcbPrivilege)
   - LSASS access detection (EventID 10, Sysmon)
   - UAC bypass process patterns (eventvwr, fodhelper, sdclt, cmstp)
   - Local admin group changes (EventID 4732/4728)
   - Scheduled task creation (EventID 4698)
   - Service creation (EventID 4697/7045)
   - Compiled regex IOC extraction (IP, hash, username, hostname, filepath)
   - Test: 11 IOCs, 4 findings, risk 95

2. **data_exfiltration real skill template** (`worker/skills/data_exfiltration.py`)
   - Large outbound transfer detection (bytes_out threshold)
   - DNS exfiltration via Shannon entropy scoring
   - File staging/compression detection (7zip, WinRAR)
   - Cloud storage upload detection (dropbox, mega.nz, etc.)
   - Compiled regex IOC extraction
   - Test: 5 IOCs extracted, but matched wrong skill (c2 template via keyword)

3. **Template string escaping patterns documented**
   - Non-raw `"""` strings: use `\\b` for regex word boundaries (renders as `\b`)
   - Mock data paths: `C:\\\\` (renders as `C:\\`)
   - Nested triple quotes: `\"\"\"` (renders as `"""`)
   - Compiled `re.compile()` preferred over IOC_PATTERNS dict for reliability

4. **Skill template count:** 9/11 real templates (was 7/11)
   - Real: brute_force, c2_comm, ransomware, phishing, lateral_movement, network_beaconing, privilege_escalation, data_exfiltration, (deobfuscation as activity)
   - Skeleton: insider_threat, supply_chain_compromise

### Session 6 (2026-03-18)

**Commits:** `d0dbf58`

**What was done:**
1. **retrieve_skill routing fix** (`_legacy_activities.py`)
   - 3-tier matching: exact threat_type → prefix match → keyword ILIKE fallback
   - Fixes data_exfiltration routing to wrong skill (was matching c2_communication_hunt via keyword)

2. **insider_threat real skill template** (`worker/skills/insider_threat.py`)
   - Off-hours login detection (configurable hours)
   - Bulk file access (count threshold)
   - USB/removable media events
   - Print job detection for sensitive documents
   - Email forwarding rules to external addresses
   - Sensitive directory access monitoring

3. **supply_chain real skill template** (`worker/skills/supply_chain.py`)
   - DLL side-loading (wrong-path detection)
   - Binary hash mismatch detection
   - Suspicious child processes from trusted software
   - Trusted binary C2 connections (SolarWinds-style)
   - Test: 9 IOCs, 4 findings, risk 95

4. **All 11/11 skill templates now real** — no more skeletons

5. **Full 6-alert test suite** (5/6 completed):
   - brute_force: 1 IOC, 2 findings, risk 95
   - lateral_movement: 4 IOCs, 5 findings, risk 90
   - privilege_escalation: 11 IOCs, 4 findings, risk 95
   - data_exfiltration: 5 IOCs, 1 finding, risk 0 (routing issue persists — needs keyword update)
   - supply_chain: 9 IOCs, 4 findings, risk 95
   - insider_threat: timed out (workflow status stuck at pending)

### Session 7 (2026-03-18) — Path B (LLM Generate) Evaluation

**Goal:** Test whether the LLM can generate investigation code from scratch (Path B) with SIEM data, bypassing templates.

**Infrastructure fixes required before testing:**
1. **retrieve_skill keyword matching was backwards** — single prompt words like "threat" matched keyword phrases like "insider threat detection" via `k ILIKE ANY(prompt_words)`. Fixed to `prompt LIKE '%' || keyword || '%'` (prompt must contain the keyword phrase).
2. **Vector similarity fallback had no threshold** — always returned closest template regardless of relevance (APT→Insider Threat at distance 0.27). **Removed entirely** — 3-tier matching (exact/prefix/keyword) is sufficient.
3. **LiteLLM database auth broken** — `litellm-database` image needs DATABASE_URL but none configured. Bypassed by pointing worker directly to Ollama (`host.docker.internal:11434`).
4. **Squid proxy blocking Ollama** — `host.docker.internal` not in NO_PROXY. Fixed.
5. **httpx timeout too short** — 120s insufficient for 14B model on 4GB VRAM GPU. Increased to 600s.
6. **qwen2.5:14b untestable** — only 33% in VRAM (3.4GB of 10GB), rest CPU offloaded. All requests timed out. Tested with deepseek-coder:6.7b instead.

**Path B Results (deepseek-coder:6.7b):**

| Test | Status | IOCs | Findings | Risk | Time |
|------|--------|------|----------|------|------|
| B1 apt_intrusion | EXEC FAILED | - | - | - | 161s |
| B2 lolbin | completed | 1/4 (25%) | 49 | 100 | 175s |
| B3 firmware | EXEC FAILED | - | - | - | 159s |
| B4 ssh_brute | completed | 3/3 (100%) | 43 | None | 114s |
| B5 pth | EXEC FAILED | - | - | - | 122s |

**Failure modes:**
- B1, B5: `<｜begin▁of▁sentence｜>` special tokens leaked into generated Python code (deepseek-coder artifact)
- B3: AttributeError — regex match returned None, no null check in generated code
- B2: IP extracted as split octets `['10','0','0','33']` instead of `'10.0.0.33'`
- B4: Perfect — all 3 expected IOCs found (10.0.0.99, admin, WEB-PROD-01)

**Honest assessment:**
- Code execution success: 40% (2/5)
- IOC extraction on completed: 57% (4/7)
- Effective IOC rate: 19% (4/21 across all tests)
- vs Path A template: 100% execution, 79% IOC rate
- **Path B is NOT production-ready** with current hardware (4GB VRAM) and models

**What we proved:**
1. SIEM injection fix WORKS — data reaches the LLM prompt correctly
2. retrieve_skill routing FIXED — 3-tier matching prevents false positives, vector similarity removed
3. When the LLM generates good code (B4), IOC extraction can be perfect
4. But code quality is unreliable — 3/5 scripts had runtime errors
5. The 14B production model is untestable on RTX 3050 — need A6000 or cloud

## Known Issues

1. **LLM code generation unreliable on 6.7B** — 40% execution rate, special token leaks, missing null checks. Path A templates remain the correct approach for the RTX 3050 hardware tier.

2. **qwen2.5:14b untestable on RTX 3050** — Only 33% fits in 4GB VRAM. Need 8GB+ VRAM (RTX 3060/4060 or better) or A6000 for standard tier.

3. **LiteLLM database auth broken** — Worker now calls Ollama directly. LiteLLM proxy needs DATABASE_URL configured to restore multi-provider fallback.

4. **fill_skill_parameters always fails** — Ollama doesn't support `response_format:json_object`. Falls back to defaults. SIEM injection fix covers this.

5. **Adversarial review times out** — AST prefilter + Docker sandbox are the actual security layers.

6. **Ground truth corpus doesn't use siem_event** — Benchmark submits alerts without SIEM events.

7. **NATS hostname resolution** — Non-fatal warning on worker startup.

## Recommended Next Steps

1. **GPU upgrade** — Get 8GB+ VRAM GPU to test qwen2.5:14b on Path B properly
2. **Post-processing for Path B** — Strip special tokens, add null checks, validate generated code before sandbox
3. **DPO training** — Fine-tune on IOC extraction examples to improve code quality
4. **Fix LiteLLM** — Add DATABASE_URL to litellm service in docker-compose for proper multi-provider routing
5. **Update benchmark corpus** — Add siem_event payloads to test the real investigation path
