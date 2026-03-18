# HYDRA Research Prompt — Session Context for LLMs

> Paste this into any LLM session to give it full context on the HYDRA project state.
> Last updated: 2026-03-18, commit cddf7e1

## Project Overview

HYDRA is an air-gapped, on-premise AI SOC platform. It receives SIEM alerts, generates Python investigation code via LLM, executes it in a sandboxed Docker container, and delivers structured verdicts with findings, IOCs, risk scores, and recommendations.

**Stack:** Go API + Python Temporal Worker + React Dashboard + PostgreSQL/pgvector + Redis + NATS + LiteLLM + Ollama

## Current State

- **Version:** post v1.0.0-rc1
- **Latest commit:** `cddf7e1` (privilege_escalation + data_exfiltration real templates)
- **Pipeline:** OPERATIONAL — investigations complete end-to-end
- **LLM:** Ollama qwen2.5:14b (local, RTX 3050) via LiteLLM
- **Tests:** 44 Go + 179 Python = 223 test functions
- **Services:** 17 Docker containers
- **Skills:** 11 in DB (9 with real templates, 2 skeleton)
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

**IOC extraction on SIEM events: 100% (4/4 had IOCs)**
**Mean IOCs per investigation: 5.5**

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

**Current reality:** All 12 task type categories match a skill via keyword, so Path B (v2 prompts) is unreachable. Path A always runs.

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

## Known Issues

1. **v2 generate_code path unreachable** — All task types match a skill template via keyword in `retrieve_skill`. Path B (PromptAssembler) never fires. The retry loop is the only way v2 prompts get used.

2. **2 skeleton templates remain** — insider_threat, supply_chain_compromise have placeholder templates with no real detection logic. They produce 0 IOCs and 0 findings.

3. **fill_skill_parameters always fails** — Ollama doesn't support `response_format:json_object`. Falls back to defaults every time. Our SIEM injection fix covers this, but parameter extraction from prompts doesn't work.

4. **Adversarial review times out** — urllib-based LLM call against Ollama times out. AST prefilter + Docker sandbox are the actual security layers.

5. **generate_followup_code uses fast model** — Now routes through Ollama (was failing on dead cloud providers). May succeed but quality depends on qwen2.5:14b capability.

6. **Ground truth corpus doesn't use siem_event** — The 70-alert benchmark submits alerts without SIEM events, so IOC extraction via the SIEM injection fix isn't tested by the benchmark.

7. **NATS hostname resolution** — Non-fatal warning on worker startup. Consumer initializes despite it.

## Recommended Next Steps

1. **Write real skill templates** for remaining 2 skeleton types (insider_threat, supply_chain_compromise)
2. **Update ground truth corpus** to include `siem_event` payloads so the benchmark tests the SIEM injection path
3. **DPO Phase 2-4** — Generate training data, train model, measure accuracy delta
4. **Fix retrieve_skill** to fall through to generate_code when template produces 0 IOCs (alternative to retry loop)
5. **Full benchmark** with updated corpus
