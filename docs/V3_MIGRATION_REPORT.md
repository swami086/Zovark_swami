# Zovark v3 Migration Report — Deterministic Tool-Calling Architecture

## Summary

Zovark v3 replaces the Docker sandbox code execution pipeline with a deterministic tool-calling architecture. Instead of generating Python code via LLM and executing it in a sandboxed container, v3 uses 34 pre-built investigation tools orchestrated by saved plans or LLM-selected tool sequences.

## Architecture Comparison

### v2 Pipeline (Sandbox)
```
SIEM Alert → INGEST → ANALYZE (LLM generates Python code)
  → EXECUTE (AST prefilter + Docker sandbox) → ASSESS → STORE
```

### v3 Pipeline (Tool-Calling)
```
SIEM Alert → INGEST → ANALYZE (load saved plan OR LLM selects tools)
  → EXECUTE (in-process tool runner) → ASSESS → GOVERN → STORE
```

### Key Differences

| Aspect | v2 (Sandbox) | v3 (Tool-Calling) |
|--------|-------------|-------------------|
| Code execution | LLM-generated Python in Docker | 34 deterministic tool functions |
| Security model | AST prefilter + sandbox isolation | Tool catalog allowlist + no code gen |
| Speed (Path A) | ~350ms (template render + sandbox) | ~5ms (plan load + tool calls) |
| Speed (Path C) | ~120s (LLM code gen + sandbox) | ~30s (LLM tool selection + tool calls) |
| LLM usage | Code generation (8B model) | Tool selection (3B model) |
| Failure mode | Crash → risk=0, safety wrapper | Tool error → isolated, others continue |
| New features | — | Correlation, institutional knowledge, governance |

## Tool Library (34 tools, 7 categories)

### Extraction (8 tools)
| Tool | Description |
|------|-------------|
| extract_ipv4 | IPv4 addresses with evidence_refs, excludes loopback/broadcast/RFC5737 |
| extract_ipv6 | IPv6 addresses, excludes ::1 |
| extract_domains | Domain names with TLD validation, excludes localhost/example.com |
| extract_urls | Full URLs (http/https/ftp) |
| extract_hashes | MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex) |
| extract_emails | Email addresses |
| extract_usernames | From SIEM patterns: User=, TargetUserName=, SubjectUserName= |
| extract_cves | CVE identifiers (CVE-YYYY-NNNNN) |

### Analysis (4 tools)
| Tool | Description |
|------|-------------|
| count_pattern | Regex pattern match count |
| calculate_entropy | Shannon entropy of a string |
| detect_encoding | Detect base64, hex, URL encoding |
| check_base64 | Find and decode base64 strings |

### Parsing (5 tools)
| Tool | Description |
|------|-------------|
| parse_windows_event | Windows event log key=value pairs |
| parse_syslog | Standard syslog format |
| parse_auth_log | Auth logs: action, username, source_ip |
| parse_dns_query | DNS query logs |
| parse_http_request | HTTP CLF/Combined log format |

### Scoring (6 tools)
| Tool | Description |
|------|-------------|
| score_brute_force | Risk from failure count, velocity, unique sources |
| score_phishing | Risk from URLs, suspicious domains, credential forms |
| score_lateral_movement | Risk from method, admin shares, pass-the-hash |
| score_exfiltration | Risk from volume, external dest, off-hours |
| score_c2_beacon | Risk from interval regularity, DGA entropy |
| score_generic | Generic risk from indicator counts and severity |

### Detection (7 tools)
| Tool | Description |
|------|-------------|
| detect_kerberoasting | RC4 encryption, TGS requests, SPN abuse |
| detect_golden_ticket | Forged TGT, abnormal lifetime |
| detect_ransomware | Shadow copy deletion, mass encryption |
| detect_phishing | Suspicious URLs, credential harvesting |
| detect_c2 | Beacon intervals, DGA domains |
| detect_data_exfil | Large transfers, off-hours, external dest |
| detect_lolbin_abuse | certutil, mshta, bitsadmin abuse |

### Enrichment (4 tools)
| Tool | Description |
|------|-------------|
| map_mitre | MITRE ATT&CK technique mapping (40+ techniques) |
| lookup_known_bad | Local known-bad IOC list |
| correlate_with_history | Cross-investigation IOC correlation |
| lookup_institutional_knowledge | Analyst-provided baselines |

## Investigation Plans

24 attack type plans covering all existing skill templates plus:
- Conditional branching (e.g., failure count > 50 → brute force scoring vs generic)
- Boolean conditions (e.g., escalation_recommended → expanded MITRE mapping)
- Benign routing (password_change, health_check, etc. → minimal 2-step plan)

## Governance Layer

New stage between ASSESS and STORE:

| Level | Behavior |
|-------|----------|
| observe | All investigations require analyst review |
| assist | Only non-benign investigations require review |
| autonomous | Only edge cases (inconclusive, error) require review |

Configurable per tenant and per task_type via `governance_config` table.

## Database Changes

Migration `062_v3_tool_calling.sql`:
- `agent_skills.investigation_plan` (JSONB) — saved tool plans
- `agent_skills.execution_mode` (VARCHAR) — "sandbox" or "tools"
- `governance_config` table — autonomy levels per tenant
- `institutional_knowledge` table — analyst-provided baselines
- `analyst_feedback` expanded — investigation_notes, environment_baseline, missing_context

## Red Team Results

21 security tests across 5 categories, **0 critical vulnerabilities**:

| Category | Tests | Result |
|----------|-------|--------|
| Tool argument injection | 6 | All safe — SQL, path traversal, large inputs, null bytes, Unicode |
| Variable resolution injection | 5 | All safe — __class__, __globals__, import injection, newline |
| Plan manipulation | 4 | All safe — unknown tools blocked, DoS timeout, risk suppression |
| Conditional bypass | 3 | All safe — code injection, None handling, type coercion |
| Enrichment safety | 3 | All safe — large IOC lists, XSS storage, fabricated history |

## Test Results

| Suite | Count | Result |
|-------|-------|--------|
| Tool unit tests | 93 | All pass |
| Runner tests | 32 | All pass |
| Red team v3 tests | 21 | All pass |
| v2 regression tests | 364 | 360 pass + 4 pre-existing |
| **Total** | **510** | **506 pass** |

## Feature Flag

v2 sandbox code is preserved behind `ZOVARK_EXECUTION_MODE` environment variable:
- `tools` (default) — v3 tool-calling pipeline
- `sandbox` — v2 Docker sandbox pipeline

Instant rollback: set `ZOVARK_EXECUTION_MODE=sandbox` and restart worker.

## Lines Changed

| Category | Added | Removed | Net |
|----------|-------|---------|-----|
| Tool library | 1,200 | 0 | +1,200 |
| Tool runner | 280 | 0 | +280 |
| Investigation plans | 500 | 0 | +500 |
| Pipeline rewrites | 370 | 0 | +370 |
| Governance stage | 90 | 0 | +90 |
| Tests | 750 | 0 | +750 |
| DB migration | 50 | 0 | +50 |
| **Total** | **3,240** | **0** | **+3,240** |

Note: v2 code is preserved (0 lines removed from critical path). The ~580 lines of sandbox infrastructure are behind the feature flag, not deleted.

## Conifers-Inspired Features

| Feature | Conifers CognitiveSOC | Zovark v3 |
|---------|----------------------|-----------|
| Deterministic tools | Yes — tool-calling architecture | Yes — 34 tools, saved plans |
| Alert correlation | Yes — cross-investigation linking | Yes — correlate_with_history |
| Institutional knowledge | Yes — analyst baselines | Yes — institutional_knowledge table |
| Governance/autonomy | Yes — observe/assist/autonomous | Yes — governance_config |
| Air-gap deployment | No — cloud-only | Yes — full air-gap support |
