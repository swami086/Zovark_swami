# HYDRA — Claude Code Multi-Agent Prompt Set
### Copy-paste ready. Each prompt is designed to spawn parallel sub-tasks.

---

## HOW THESE PROMPTS WORK

Each prompt below uses a **multi-agent decomposition pattern**. Instead of giving Claude Code one monolithic task, each prompt:

1. Defines the GOAL in one sentence
2. Lists 3–5 PARALLEL AGENTS (sub-tasks that can be worked independently)
3. Specifies a MERGE step where agents' outputs combine
4. Defines VERIFICATION that proves the work is correct

Claude Code will treat each agent as an independent work stream, complete them in sequence, then merge and verify. This prevents the "2,000-line monolith" failure mode.

**Before ANY prompt:** Always start a fresh session with the context load:

```
cat docs/HYDRA_COMPLETE_CONTEXT.md
git log --oneline -5
docker compose ps --format "table {{.Name}}\t{{.Status}}" | head -20
docker compose logs worker --tail 3 2>&1 | grep -v NATS
```

---

## PROMPT 0: CREDENTIAL SCRUB + DEAD SERVICE CLEANUP

```
GOAL: Remove all hardcoded credentials from documentation and kill non-functional Docker services.

=== AGENT 1: CREDENTIAL HUNTER ===
Scan every file in docs/, worker/, api/, scripts/, and root directory for these patterns:
  - "hydra-redis-dev-2026" (Redis password)
  - "TestPass2026" (admin password)
  - "admin@test.local" (admin email used as credential)
  - "sk-hydra" (any API keys)
  - Any string that looks like a password, token, or secret in a config/doc file

For each match:
  - Replace with environment variable reference: ${HYDRA_REDIS_PASSWORD}, ${HYDRA_ADMIN_PASSWORD}, etc.
  - If in a markdown doc, replace with <REDACTED> and add a note: "Set via environment variable"

Create secrets.env.example with all extracted variables and placeholder values.
Add .env and secrets.env to .gitignore if not already present.
Do NOT touch docker-compose.yml env vars that already use ${} syntax — those are correct.

=== AGENT 2: DEAD SERVICE KILLER ===
Read docker-compose.yml. Identify services that are:
  - NATS / nats-streaming — non-functional, throwing connection warnings
  - TEI / embedding-server / text-embeddings-inference — not running
  - LiteLLM / litellm-proxy — bypassed (LITELLM_URL goes direct to llama-server)

Move these services to a new file: docker-compose.optional.yml
Update any depends_on references in the main docker-compose.yml.
Ensure the core stack (api, worker, temporal, postgres, pgbouncer, redis, sandbox) still starts clean.

=== AGENT 3: TEMPORAL CLEANUP ===
Write a script: scripts/cleanup_temporal.sh that:
  1. Lists all open workflows: tctl workflow list --status open
  2. Terminates any ExecuteTaskWorkflow (V1 legacy) workflows
  3. Reports count of terminated workflows
  4. Verifies only InvestigationWorkflowV2 workflows remain

=== MERGE ===
Run: docker compose down && docker compose up -d
Verify: docker compose ps shows exactly 7-8 healthy services, zero NATS warnings in worker logs.
Run: grep -rn "TestPass2026\|hydra-redis-dev-2026\|sk-hydra" docs/ worker/ api/ scripts/ — must return ZERO matches.
Commit: "security: scrub credentials from docs, remove dead services, clean Temporal history"
```

---

## PROMPT 1: NEMOTRON 4B MODEL BENCHMARK

```
GOAL: Download Nemotron 3 Nano 4B GGUF, run it alongside current Qwen2.5-14B, and produce a head-to-head accuracy + speed comparison on HYDRA's investigation pipeline.

=== IMPORTANT CONTEXT ===
Current LLM: Qwen2.5-14B-Instruct-Q4_K_M.gguf via llama-server on native Windows
LLM endpoint: http://host.docker.internal:11434/v1/chat/completions
llama-server binary: C:\Users\vinay\llama-cpp\llama-server.exe
Models directory: C:/Users/vinay/models/
Worker env var: LITELLM_URL=http://host.docker.internal:11434/v1/chat/completions
Hardware: RTX 3050 4GB VRAM, 24GB system RAM
V2 pipeline: analyze.py (Stage 2) and assess.py (Stage 4) make LLM calls via httpx to LITELLM_URL
The pipeline has 11 skill templates: brute-force, c2-communication, cloud-infrastructure, data-exfiltration, insider-threat, lateral-movement, network-beaconing, phishing, privilege-escalation, ransomware, supply-chain

=== AGENT 1: MODEL DOWNLOAD + VALIDATION ===
Download Nemotron 3 Nano 4B Q4_K_M GGUF:
  huggingface-cli download nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF --local-dir C:/Users/vinay/models/nemotron-4b/

Verify the file exists and check its size (should be ~2.5GB).
Verify it works with llama-server:
  C:\Users\vinay\llama-cpp\llama-server.exe -m C:/Users/vinay/models/nemotron-4b/Nemotron-3-Nano-4B-Q4_K_M.gguf -ngl 99 --port 11435
  curl http://localhost:11435/v1/models

Note: Nemotron 3 Nano 4B uses <think> and </think> tokens for reasoning.
The chat template uses <|im_start|> and <|im_end|> (same as Qwen).
If llama-server needs --special flag, add it.

=== AGENT 2: BENCHMARK CORPUS BUILDER ===
Create scripts/nemotron_benchmark.py that:
1. Defines 11 test alerts — one per skill template type — with realistic SIEM event payloads
2. Each alert includes:
   - task_type matching a skill template
   - siem_event with: title, source_ip, destination_ip, hostname, username, rule_name, raw_log
   - severity (mix of critical, high, medium)
   - ground_truth: expected verdict (true_positive, false_positive, suspicious, benign)
   - expected_iocs: list of IOCs that should be found
3. Exports as both JSON file (benchmark_corpus_11.json) and Python dict

Example alert structure:
{
  "task_type": "phishing_investigation",
  "severity": "high",
  "siem_event": {
    "title": "Suspicious URL in email",
    "source_ip": "10.0.0.42",
    "destination_ip": "203.0.113.50",
    "hostname": "WS-ANALYST-07",
    "username": "jsmith",
    "rule_name": "Email_Phishing_URL",
    "raw_log": "GET /secure-login.php?token=abc123 HTTP/1.1 Host: secure-update.xyz User-Agent: Mozilla/5.0"
  },
  "ground_truth": {
    "verdict": "true_positive",
    "expected_iocs": ["203.0.113.50", "secure-update.xyz"],
    "expected_risk_range": [70, 100]
  }
}

=== AGENT 3: BENCHMARK RUNNER ===
Create scripts/model_benchmark.py that:
1. Takes CLI args: --model-url (LLM endpoint), --model-name (label), --corpus (JSON file path), --api-url (HYDRA API)
2. Authenticates with HYDRA API (admin@test.local credentials from env var)
3. Flushes Redis dedup cache before starting
4. Submits each alert, polls for completion (max 5 min per alert)
5. For each completed investigation, records:
   - investigation_time_seconds
   - verdict (from output)
   - verdict_correct (compared to ground_truth)
   - iocs_found (list)
   - ioc_recall (% of expected IOCs found)
   - risk_score
   - risk_in_range (boolean)
   - code_generated (first 200 chars of generated code for manual review)
   - summary (LLM-generated summary)
   - status (completed/failed/timeout)
6. Outputs results to benchmark_results_{model_name}.json
7. Prints summary table:
   Model | Completed | Accuracy | IOC Recall | Avg Time | Median Time

=== AGENT 4: HEAD-TO-HEAD RUNNER SCRIPT ===
Create scripts/run_model_comparison.sh that:
1. Runs benchmark with current Qwen2.5-14B (llama-server on port 11434):
   python scripts/model_benchmark.py --model-url http://localhost:11434/v1/chat/completions --model-name qwen25-14b --corpus scripts/benchmark_corpus_11.json --api-url http://localhost:8090

2. Stops Qwen llama-server, starts Nemotron 4B on same port (or different port — update LITELLM_URL):
   NOTE: This requires manual model swap on Windows. Script should print instructions:
   "Stop current llama-server. Start: llama-server.exe -m nemotron-4b/Nemotron-3-Nano-4B-Q4_K_M.gguf -ngl 99 --port 11434"
   Then wait for user confirmation before proceeding.

3. Runs same benchmark with Nemotron 4B:
   python scripts/model_benchmark.py --model-url http://localhost:11434/v1/chat/completions --model-name nemotron-4b --corpus scripts/benchmark_corpus_11.json --api-url http://localhost:8090

4. Generates comparison report: scripts/model_comparison_report.py
   - Reads both result files
   - Produces markdown table comparing all metrics
   - Recommends: which model for which tier
   - Saves to docs/MODEL_COMPARISON.md

=== MERGE ===
All scripts must be in scripts/ directory.
Verify: python scripts/nemotron_benchmark.py --help (should print usage)
Verify: python scripts/model_benchmark.py --help (should print usage)
Commit: "feat: Nemotron 4B vs Qwen 14B benchmark suite — 11 skill templates, head-to-head comparison"
```

---

## PROMPT 2: NEMOCLAW SANDBOX HARDENING (PATTERN ADOPTION)

```
GOAL: Adopt 3 architecture patterns from NVIDIA NemoClaw/OpenShell into HYDRA's sandbox and LLM layers — WITHOUT adding NemoClaw as a dependency. We build our own lightweight versions.

=== IMPORTANT CONTEXT ===
Read these files first:
  cat worker/stages/execute.py
  cat worker/stages/analyze.py
  cat worker/stages/assess.py
  cat sandbox/ (if directory exists, read all files)
  cat docker-compose.yml | grep -A20 sandbox

Current sandbox: worker/stages/execute.py runs investigation code in a Docker container with:
  - AST prefilter blocking: os, sys, subprocess, socket, dunder traversal
  - Network isolation (Docker network mode)
  - Read-only filesystem
  - cap-drop ALL
  - Kill timer for execution timeout

NemoClaw patterns to adopt:
1. Declarative YAML sandbox policy (replaces hardcoded Docker settings)
2. LLM audit gateway (logs every LLM call with metadata)
3. Model routing config (maps alert severity/type → model endpoint)

=== AGENT 1: SANDBOX POLICY YAML ===
Create worker/stages/sandbox_policy.yaml:

```yaml
# HYDRA Sandbox Security Policy v1.0
# This file defines what investigation code can and cannot do.
# Customers can audit and customize this file.
version: "2026-03"

filesystem:
  allow:
    - "/sandbox/**"          # Investigation working directory
    - "/tmp/**"              # Temporary files
  deny:
    - "/etc/**"              # System config
    - "/proc/**"             # Process info
    - "/sys/**"              # Kernel params
    - "/var/**"              # System state
    - "/home/**"             # User data
  mode: "read-only-root"     # Root filesystem is read-only

network:
  mode: "deny-all"           # No outbound network by default
  # Future: allow specific IOC lookup services
  # allow_domains:
  #   - "api.abuseipdb.com"
  #   - "www.virustotal.com"

process:
  blocked_syscalls:
    - "ptrace"               # No debugging other processes
    - "mount"                # No filesystem mounting
    - "reboot"               # No system reboot
  blocked_capabilities:
    - "ALL"                  # Drop all Linux capabilities
  max_execution_seconds: 120
  max_memory_mb: 512

ast_prefilter:
  blocked_imports:
    - "os"
    - "sys"
    - "subprocess"
    - "socket"
    - "shutil"
    - "ctypes"
    - "importlib"
  blocked_patterns:
    - "__import__"
    - "eval("
    - "exec("
    - "compile("
    - "getattr("
    - "__subclasses__"
    - "__builtins__"
```

Update worker/stages/execute.py to:
1. Load sandbox_policy.yaml at module level
2. Use policy values for AST prefilter blocked_imports list (instead of hardcoded)
3. Use policy values for Docker container settings (timeout, memory limit, capabilities)
4. Log which policy version was used for each execution
5. Keep backward compatibility — if sandbox_policy.yaml is missing, use hardcoded defaults

=== AGENT 2: LLM AUDIT GATEWAY ===
Create worker/stages/llm_gateway.py — a thin wrapper around httpx LLM calls.

Every LLM call in analyze.py and assess.py should go through this gateway instead of calling httpx directly.

The gateway function signature:
```python
async def llm_call(
    prompt: str,
    system_prompt: str,
    model_config: dict,
    task_id: str,
    stage: str,  # "analyze" or "assess"
    task_type: str,
) -> dict:
    """
    Makes LLM call and logs audit metadata.
    Returns: {"content": str, "tokens_in": int, "tokens_out": int, "latency_ms": int}
    """
```

The gateway must:
1. Call the LLM endpoint via httpx (same as current code)
2. Measure latency (start/end time)
3. Extract token counts from response
4. Log to a new PostgreSQL table `llm_audit_log`:
   - id (UUID)
   - task_id (UUID)
   - tenant_id (UUID)
   - stage (text: "analyze" or "assess")
   - task_type (text)
   - model_name (text: from model_config)
   - tokens_in (int)
   - tokens_out (int)
   - latency_ms (int)
   - prompt_hash (text: SHA-256 of prompt — NOT the prompt itself, for privacy)
   - status (text: "success" or "error")
   - error_message (text, nullable)
   - created_at (timestamptz)
5. NOT log the actual prompt or response (customer data stays private)
6. Return the response dict

Create the migration: migrations/041_llm_audit_log.sql

Update analyze.py:
  - Import llm_call from llm_gateway
  - Replace the httpx calls at line 244 and line 349 with llm_call()
  - Pass task_id, stage="analyze", task_type from the ingested data

Update assess.py:
  - Import llm_call from llm_gateway  
  - Replace the httpx call at line 69 with llm_call()
  - Pass task_id, stage="assess", task_type

CRITICAL: Do NOT break the existing FAST_FILL bypass. The FAST_FILL check must remain ABOVE the llm_call invocation.

=== AGENT 3: MODEL ROUTING CONFIG ===
Create worker/stages/model_config.yaml:

```yaml
# HYDRA Model Routing Configuration
# Maps investigation parameters to model endpoints
version: "2026-03"

models:
  fast:
    name: "nemotron-4b"
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    model: "nemotron-3-nano-4b"
    max_tokens: 4096
    temperature: 0.1
    timeout_seconds: 120
    description: "Fast tier — Nemotron 3 Nano 4B for simple triage"

  standard:
    name: "qwen25-14b"
    endpoint: "http://host.docker.internal:11434/v1/chat/completions"
    model: "qwen2.5-14b-instruct"
    max_tokens: 8192
    temperature: 0.1
    timeout_seconds: 300
    description: "Standard tier — Qwen2.5-14B for full investigation"

  enterprise:
    name: "nemotron-super-120b"
    endpoint: "http://localhost:8080/v1/chat/completions"
    model: "nemotron-3-super-120b"
    max_tokens: 16384
    temperature: 0.1
    timeout_seconds: 600
    description: "Enterprise tier — Nemotron 3 Super for complex analysis (requires A100)"

routing:
  # Default model for all investigations
  default: "standard"

  # Override by severity
  severity_overrides:
    low: "fast"
    medium: "standard"
    high: "standard"
    critical: "standard"

  # Override by task type (optional, uncomment to enable)
  # task_type_overrides:
  #   phishing_investigation: "fast"
  #   ransomware_triage: "standard"
  #   supply_chain_compromise: "enterprise"
```

Create worker/stages/model_router.py:
1. Loads model_config.yaml
2. Function: get_model_config(severity: str, task_type: str) -> dict
   - Checks task_type_overrides first
   - Then severity_overrides
   - Falls back to default
   - Returns the full model config dict
3. Falls back to LITELLM_URL env var if yaml is missing (backward compat)

Update llm_gateway.py to accept model_config from the router.
Update analyze.py to call get_model_config() before making LLM call.
Update assess.py to call get_model_config() before making LLM call.

=== MERGE ===
Verify: grep -n "httpx" worker/stages/analyze.py worker/stages/assess.py
  — httpx should now ONLY appear inside llm_gateway.py, NOT in analyze.py or assess.py
Verify: python -c "import yaml; yaml.safe_load(open('worker/stages/sandbox_policy.yaml'))" — no errors
Verify: python -c "import yaml; yaml.safe_load(open('worker/stages/model_config.yaml'))" — no errors
Verify: docker compose exec -e HYDRA_FAST_FILL=true -e DEDUP_ENABLED=false worker python -m pytest test_pipeline_v2.py -v --tb=short
  — All 15 tests must still pass

Commit: "feat: NemoClaw-inspired sandbox policy, LLM audit gateway, model routing — enterprise security patterns"
```

---

## PROMPT 3: SOC ANALYST DASHBOARD (THE MONEY SHOT)

```
GOAL: Build the HYDRA SOC Analyst Dashboard — 3 views (Login, Alert Queue, Investigation Detail) in the existing React 19 + Vite 7 + Tailwind 4 dashboard/ directory. Dark mode, information-dense, SOC-analyst aesthetic.

=== IMPORTANT CONTEXT ===
Read the existing dashboard setup:
  ls dashboard/
  cat dashboard/package.json
  cat dashboard/src/App.tsx (or main entry file)
  cat dashboard/vite.config.ts
  cat dashboard/tailwind.config.ts (or .js)

API endpoints (Go API on port 8090):
  POST /api/v1/auth/login — body: {"email":"...","password":"..."} → {"token":"..."}
  GET  /api/v1/tasks — list all tasks (requires Bearer token)
  GET  /api/v1/tasks/:id — get single task with full output (requires Bearer token)
  POST /api/v1/tasks — create task (requires Bearer token)

Task object shape (from API):
{
  "id": "uuid",
  "tenant_id": "uuid", 
  "task_type": "phishing_investigation",
  "status": "completed",  // pending, running, completed, failed
  "input": {
    "prompt": "...",
    "severity": "high",
    "siem_event": {
      "title": "...",
      "source_ip": "10.0.0.42",
      "destination_ip": "203.0.113.50",
      "hostname": "WS-ANALYST-07",
      "username": "jsmith",
      "rule_name": "...",
      "raw_log": "..."
    }
  },
  "output": {
    "findings": [...],
    "iocs": [{"type": "ip", "value": "203.0.113.50", "severity": "high"}, ...],
    "risk_score": 85,
    "verdict": "true_positive",  // true_positive, false_positive, suspicious, benign
    "summary": "Investigation found malicious phishing URL...",
    "recommendations": [...]
  },
  "created_at": "2026-03-21T10:00:00Z",
  "updated_at": "2026-03-21T10:00:52Z"
}

=== DESIGN DIRECTION ===
Category: Developer/SOC Tool — DARK MODE
Background: #0f0f11
Surface/cards: #1a1a1e with border 1px solid rgba(255,255,255,0.06)
Text primary: #e4e4e7
Text secondary: #71717a
Accent: #3b82f6 (blue — active states, links)
Font body: system-ui, -apple-system, sans-serif (fast load, clean)
Font mono: JetBrains Mono (IPs, hashes, timestamps, code) — load from Google Fonts
Verdict colors: true_positive=#ef4444, false_positive=#22c55e, suspicious=#f59e0b, benign=#6b7280
Severity colors: critical=#dc2626, high=#ef4444, medium=#f59e0b, low=#3b82f6
Status colors: pending=#71717a (pulsing), running=#3b82f6 (spinner), completed=#22c55e, failed=#ef4444
Border radius: 6px buttons, 8px cards
Shadow: none (flat + borders, like Linear)
Density: HIGH — 13px body text, tight padding, SOC analysts are power users
Reference: Datadog incident view, CrowdStrike Falcon, Linear app

=== AGENT 1: AUTH + ROUTING + LAYOUT SHELL ===
Build the app skeleton:

1. src/lib/api.ts — API client
   - Base URL from env var VITE_API_URL (default http://localhost:8090)
   - login(email, password) → stores JWT in memory (NOT localStorage)
   - fetchTasks() → GET /api/v1/tasks with Bearer token
   - fetchTask(id) → GET /api/v1/tasks/:id with Bearer token
   - Auto-redirect to login on 401

2. src/hooks/useAuth.ts — Auth context
   - Stores token in React state (memory only — secure)
   - isAuthenticated boolean
   - login/logout functions

3. src/App.tsx — Router
   - /login → LoginPage
   - / → AlertQueue (protected)
   - /investigation/:id → InvestigationDetail (protected)
   - Redirect to /login if not authenticated

4. src/components/Layout.tsx — App shell
   - Top nav bar (64px height): HYDRA logo (text), pipeline status indicator, logout button
   - Full-width content area below nav
   - No sidebar (keep it simple for MVP)

=== AGENT 2: LOGIN PAGE ===
src/pages/LoginPage.tsx

- Centered card on dark background
- HYDRA logo/text at top (large, bold)
- Subtitle: "SOC Investigation Platform"
- Email input + Password input (44px height, dark input fields)
- "Sign In" button (blue accent, full width)
- Error state: red border on inputs + error message below
- Loading state: spinner in button, inputs disabled
- On success: redirect to /
- Auto-focus email input on mount
- NO "remember me", NO "forgot password" — MVP

=== AGENT 3: ALERT QUEUE PAGE ===
src/pages/AlertQueue.tsx

This is the home screen. A real-time table of investigations.

Header section:
- Page title: "Investigations" (20px, weight 600)
- Right side: count badges — "12 Pending · 3 Running · 145 Completed"
- Filter pills below: All | Pending | Running | Completed | True Positive | False Positive | Suspicious
  - Active pill: blue background
  - Inactive pill: transparent with border

Table columns:
| Column | Width | Content |
|--------|-------|---------|
| Severity | 80px | Badge: CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (blue) — small caps, 11px |
| Alert | flex | task_type formatted (replace _ with space, title case) + siem_event.title below in secondary text |
| Source | 140px | siem_event.source_ip in monospace |
| Host | 120px | siem_event.hostname in monospace |
| Status | 100px | Badge: pending (gray pulsing dot), running (blue spinning), completed (green check), failed (red x) |
| Verdict | 120px | Badge with verdict color — only shown if completed |
| Risk | 60px | risk_score number, colored: 80+ red, 50-79 yellow, <50 green |
| Time | 100px | Relative time: "2m ago", "1h ago" — use created_at |

Row behavior:
- Hover: background brightens slightly (rgba(255,255,255,0.02))
- Click: navigate to /investigation/:id
- Running rows should feel alive — subtle pulse or spinner

Polling:
- Fetch tasks every 5 seconds
- Preserve scroll position and selected filter on refresh
- New tasks should appear at top (sort by created_at desc)

Empty state: "No investigations yet. Submit an alert to begin."

=== AGENT 4: INVESTIGATION DETAIL PAGE ===
src/pages/InvestigationDetail.tsx

This is the page that sells HYDRA. Load task by ID from URL param.

Section 1 — Header Bar (sticky top):
- Back arrow (← link to /)
- Alert title (task_type formatted)
- Severity badge
- Verdict badge (large, prominent)
- Risk score: circular gauge or large number with color
- Investigation duration: "Completed in 52s" (calculated from created_at to updated_at)

Section 2 — Summary (the star):
- Card with output.summary text
- Full width, generous padding
- If still running: "Investigation in progress..." with skeleton loading

Section 3 — Pipeline Timeline:
- Horizontal 5-stage bar:
  INGEST → ANALYZE → EXECUTE → ASSESS → STORE
- Each stage shows:
  - Stage name
  - Status icon (check for complete, spinner for running, dot for pending)
  - Duration if available
- This is unique to HYDRA — make it visually distinctive
- Use a connected progress bar style, not just 5 dots

Section 4 — IOCs (Indicators of Compromise):
- Table: Type | Value | Severity
- Type badges: IP (blue), Domain (purple), Hash (gray), URL (orange), Email (teal)
- Value in monospace
- If no IOCs: "No indicators of compromise found"

Section 5 — Findings:
- output.findings rendered as a list of cards or text blocks
- Each finding as a distinct item with a bullet or number

Section 6 — Recommendations:
- output.recommendations as a simple list

Section 7 — Raw Data (collapsed by default):
- Toggle button: "Show Raw Data"
- When expanded: JSON of full task object, formatted with syntax highlighting
- Use a <pre> tag with monospace font, dark background

Loading state: Full page skeleton with pulsing placeholder blocks
Error state: "Investigation not found" with back link
If investigation is still running: poll every 3 seconds until completed

=== AGENT 5: COMPONENTS + POLISH ===
Build shared components:

src/components/Badge.tsx — Reusable badge (severity, verdict, status, IOC type)
src/components/StatusDot.tsx — Pulsing dot for pending, spinning for running
src/components/RiskScore.tsx — Colored number or mini gauge
src/components/RelativeTime.tsx — "2m ago" from timestamp
src/components/PipelineTimeline.tsx — The 5-stage horizontal progress bar
src/components/JsonViewer.tsx — Formatted JSON display

Polish checklist:
- All text must be legible on dark background (check contrast ratios)
- Monospace font loaded: <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap">
- No white flash on page load (set background in index.html body tag)
- Loading states on every data fetch
- Error boundaries on each page
- Console should be clean — no React warnings

=== MERGE ===
Run: cd dashboard && npm install && npm run build — must complete with zero errors
Run: npm run dev — open in browser, verify:
  1. Login page renders, dark mode, centered card
  2. Login with admin@test.local / TestPass2026 (or env var) → redirects to /
  3. Alert queue shows investigations (if any exist) or empty state
  4. Click an investigation → detail page loads with all sections
  5. Back button returns to queue
  6. Polling updates queue every 5 seconds

Commit: "feat: SOC analyst dashboard — dark mode, real-time alert queue, investigation detail with pipeline timeline"
```

---

## PROMPT 4: ALERT SIMULATOR + SIEM INTEGRATION DOC

```
GOAL: Build a continuous alert generator for demos and a SIEM webhook integration guide.

=== AGENT 1: ALERT GENERATOR ===
Create scripts/alert_generator.py that:

1. Imports alert templates from scripts/alert_corpus_100.py (already exists)
   If that file doesn't exist, create 20 diverse alert templates covering all 11 skill types

2. CLI args:
   --rate: alerts per minute (default: 2)
   --total: max alerts to generate (default: unlimited)
   --api-url: HYDRA API URL (default: http://localhost:8090)
   --severity-dist: distribution string like "critical:10,high:30,medium:40,low:20" (percentages)

3. For each alert:
   - Pick random template
   - Randomize: source_ip (10.0.0.X), dest_ip (random from suspicious pool), hostname (WS-XXXX), username (from name list), timestamp
   - Submit via POST /api/v1/tasks with auth
   - Print: [HH:MM:SS] ▶ phishing_investigation | 10.0.0.42 → 203.0.113.50 | HIGH | Task: abc123
   - Sleep for 60/rate seconds

4. Graceful shutdown on Ctrl+C with summary:
   "Generated 47 alerts in 23 minutes. 42 completed, 3 running, 2 pending."

=== AGENT 2: SIEM INTEGRATION GUIDE ===
Create docs/SIEM_INTEGRATION.md:

1. Overview: HYDRA accepts alerts via REST webhook
2. Endpoint: POST /api/v1/siem/investigate (or POST /api/v1/tasks)
3. Authentication: API key or JWT Bearer token
4. Request schema with full JSON example
5. Response schema
6. Splunk configuration example (Alert Action → Webhook)
7. Elastic Watcher configuration example
8. Microsoft Sentinel Logic App example
9. Generic curl example
10. Rate limits and error handling
11. Field mapping table: which SIEM fields map to which HYDRA fields

=== MERGE ===
Verify: python scripts/alert_generator.py --rate 1 --total 3 --api-url http://localhost:8090
  — Should submit 3 alerts successfully
Commit: "feat: alert generator for demos + SIEM webhook integration guide"
```

---

## PROMPT 5: 200-ALERT ACCURACY BENCHMARK

```
GOAL: Create a labeled test corpus of 200 alerts with ground-truth verdicts and build an automated accuracy scoring system.

=== AGENT 1: CORPUS BUILDER ===
Create scripts/benchmark/build_corpus.py that generates 200 labeled alerts:

Distribution:
- 55 true_positive (real attacks across all 11 types)
- 55 false_positive (benign activity that triggers rules — developer SSH, bulk marketing email, legitimate software update, CDN traffic)
- 50 suspicious (ambiguous cases — port scan from internal IP, unusual but not malicious DNS queries)
- 40 benign (clearly normal — system health checks, backup processes, scheduled tasks)

For each alert, define:
- Full SIEM event payload (realistic raw_log, IPs, hostnames, usernames)
- ground_truth_verdict: true_positive | false_positive | suspicious | benign
- ground_truth_iocs: list of IOCs that should be found (empty for benign/FP)
- ground_truth_risk_range: [min, max] expected risk score
- difficulty: easy | medium | hard
- notes: why this is the correct verdict (for human review)

Save to: scripts/benchmark/corpus_200.json
Also save a human-readable summary: scripts/benchmark/corpus_summary.md

IMPORTANT: Make false positives realistic and tricky. Examples:
- Developer using SSH tunnel to production (looks like lateral movement)
- Marketing team sending bulk email (looks like data exfiltration)
- Penetration test traffic (looks like real attack)
- Windows Update traffic to CDN (looks like C2 beaconing)
- Automated vulnerability scanner (looks like brute force)

=== AGENT 2: BENCHMARK RUNNER ===
Create scripts/benchmark/run_benchmark.py:
1. Loads corpus_200.json
2. Submits all alerts to HYDRA (with 30-second spacing to avoid overwhelming the LLM)
3. Polls for completion (max 10 min per alert)
4. Scores each investigation against ground truth
5. Saves raw results to scripts/benchmark/results_raw.json

=== AGENT 3: ACCURACY SCORER ===
Create scripts/benchmark/score_benchmark.py:
1. Reads results_raw.json
2. Calculates:
   - Overall verdict accuracy (% correct)
   - Per-verdict accuracy (TP detection rate, FP identification rate, etc.)
   - Confusion matrix: predicted vs actual verdict
   - IOC recall (% of expected IOCs found) — only for true_positive alerts
   - IOC precision (% of reported IOCs that were expected)
   - Mean/median investigation time
   - Completion rate (% that didn't timeout or fail)
   - Accuracy by difficulty tier (easy/medium/hard)
   - Accuracy by task_type
3. Generates: docs/ACCURACY_BENCHMARK.md with:
   - Executive summary (3 sentences)
   - Overall metrics table
   - Confusion matrix
   - Per-type breakdown
   - Per-difficulty breakdown
   - Speed metrics
   - Methodology section
   - Honest assessment: "Where HYDRA struggles" section

=== MERGE ===
Verify: python scripts/benchmark/build_corpus.py — generates corpus_200.json with exactly 200 entries
Verify: python scripts/benchmark/score_benchmark.py --results scripts/benchmark/sample_results.json (create a small sample for testing the scorer)
Commit: "feat: 200-alert accuracy benchmark suite with ground-truth labels and automated scoring"
```

---

## PROMPT 6: DEPLOYMENT PACKAGE

```
GOAL: Create a self-contained deployment package that works on any Linux server with an NVIDIA GPU.

=== AGENT 1: PRODUCTION DOCKER COMPOSE ===
Create deploy/docker-compose.production.yml:
- Only the 8 core services (api, worker, temporal, temporal-ui, postgres, pgbouncer, redis, sandbox)
- Production-hardened settings:
  - restart: unless-stopped on all services
  - resource limits (memory, CPU) on each service
  - Health checks on every service
  - Logging: json-file with max-size 10m, max-file 3
  - No exposed ports except: 8090 (API), 3000 (dashboard — if served)
- Environment variables all from .env file (no hardcoded values)

Create deploy/.env.example with every variable documented:
  # HYDRA Production Configuration
  # Copy to .env and fill in values
  
  # Database
  POSTGRES_USER=hydra
  POSTGRES_PASSWORD=<CHANGE_ME>
  POSTGRES_DB=hydra
  
  # Redis
  REDIS_PASSWORD=<CHANGE_ME>
  
  # Auth
  JWT_SECRET=<CHANGE_ME_generate_with_openssl_rand_hex_32>
  ADMIN_EMAIL=admin@yourdomain.com
  ADMIN_PASSWORD=<CHANGE_ME>
  
  # LLM
  LITELLM_URL=http://host.docker.internal:11434/v1/chat/completions
  
  # Workflow
  HYDRA_WORKFLOW_VERSION=InvestigationWorkflowV2

=== AGENT 2: INSTALL + OPERATIONS SCRIPTS ===
Create deploy/scripts/:

install.sh:
  - Checks prerequisites: Docker, Docker Compose, NVIDIA driver, nvidia-container-toolkit
  - Copies .env.example to .env if .env doesn't exist
  - Pulls images
  - Runs migrations
  - Starts services
  - Runs health check
  - Prints "HYDRA is running at http://localhost:8090"

health-check.sh:
  - Checks each service: docker compose ps
  - Checks API: curl http://localhost:8090/health
  - Checks worker: docker compose logs worker --tail 1
  - Checks LLM: curl http://localhost:11434/v1/models (if configured)
  - Prints GREEN/RED status for each component

backup.sh:
  - Dumps PostgreSQL to timestamped file
  - Compresses with gzip
  - Keeps last 7 backups, deletes older

demo.sh:
  - Starts all services
  - Waits for health
  - Starts alert generator at 1 alert/30 seconds
  - Prints: "Demo mode active. Open http://localhost:8090 to see HYDRA in action."
  - Ctrl+C stops generator (services keep running)

=== AGENT 3: DOCUMENTATION ===
Create deploy/docs/:

INSTALL.md — Step-by-step installation guide
HARDWARE_GUIDE.md — GPU requirements per tier (with Nemotron model recommendations)
ADMIN_GUIDE.md — Day-to-day operations (backup, update, monitoring, troubleshooting)
UPGRADE.md — How to upgrade HYDRA to new versions

=== MERGE ===
Verify: cd deploy && docker compose -f docker-compose.production.yml config — validates without error
Verify: shellcheck deploy/scripts/*.sh — no critical errors
Commit: "feat: production deployment package — install script, health checks, demo mode, full docs"
```

---

## PROMPT 7: MULTI-MODEL TIER INTEGRATION

```
GOAL: Wire up the model routing config so HYDRA can actually switch between Nemotron 4B (fast) and Qwen 14B (standard) based on alert severity, and log which model was used for each investigation.

=== IMPORTANT CONTEXT ===
Read these files FIRST — they were created by Prompt 2:
  cat worker/stages/model_config.yaml
  cat worker/stages/model_router.py
  cat worker/stages/llm_gateway.py

If those files don't exist yet, STOP and tell me to run Prompt 2 first.

=== AGENT 1: MODEL ROUTER WIRING ===
Update worker/stages/analyze.py:
1. At the top, import get_model_config from model_router
2. In the LLM code generation path (Path C), before calling llm_call:
   - Get severity from the ingested data
   - Call model_config = get_model_config(severity, task_type)
   - Pass model_config to llm_call
3. In the template parameter fill path (Path B), same thing
4. Log which model was selected: logger.info(f"Model selected: {model_config['name']} for {task_type} (severity: {severity})")

Update worker/stages/assess.py:
1. Same pattern — get model config, pass to llm_call

=== AGENT 2: INVESTIGATION OUTPUT MODEL TRACKING ===
Update the StoreOutput and the store.py stage:
1. Add model_name field to the investigation record stored in DB
2. When writing to agent_tasks output, include: "model_used": model_config["name"]
3. When writing to investigations table, include model_name column

Create migration: migrations/042_add_model_name.sql
  ALTER TABLE investigations ADD COLUMN IF NOT EXISTS model_name TEXT DEFAULT 'unknown';
  ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS model_name TEXT DEFAULT 'unknown';

=== AGENT 3: DASHBOARD MODEL INDICATOR ===
Update the Investigation Detail page to show which model was used:
- In the header section, add a small badge: "Model: qwen25-14b" or "Model: nemotron-4b"
- Use monospace font, subtle gray badge

Update the Alert Queue to optionally show model column (hidden by default, can be toggled).

=== MERGE ===
Verify: docker compose build worker && docker compose up -d worker
Run a smoke test: submit one high-severity and one low-severity alert
Check worker logs: should see "Model selected: standard" for high, "Model selected: fast" for low
Check investigation output: model_used field should be populated
Verify dashboard shows model badge

Commit: "feat: multi-model routing — Nemotron 4B for fast tier, Qwen 14B for standard, model tracking in investigations"
```

---

## EXECUTION ORDER

Run these prompts in this sequence:

| Order | Prompt | Prereqs | Time Estimate |
|-------|--------|---------|---------------|
| 1st | Prompt 0: Credential Scrub | None | 2 hours |
| 2nd | Prompt 2: NemoClaw Patterns | Prompt 0 | 4 hours |
| 3rd | Prompt 3: Dashboard | Prompt 0 | 2-3 days |
| 4th | Prompt 4: Alert Simulator | Prompt 0 | 3 hours |
| 5th | Prompt 1: Nemotron Benchmark | Prompt 0 | 4 hours (+ manual model swap) |
| 6th | Prompt 7: Multi-Model Wiring | Prompt 2 + Prompt 1 results | 3 hours |
| 7th | Prompt 5: Accuracy Benchmark | Prompt 2 + Prompt 4 | 1 day (+ overnight run) |
| 8th | Prompt 6: Deployment Package | All above | 4 hours |

Total estimated: 8-10 days of focused work.

---

## NOTES ON MULTI-AGENT PATTERN

Each prompt above is structured so Claude Code can:
1. Read the AGENT sections as independent work packages
2. Complete them in sequence without context dependency between agents
3. Merge results at the end with clear verification steps

If Claude Code tries to do everything in one giant code block, tell it:
"Work on AGENT 1 first. Show me the result. Then move to AGENT 2."

This prevents the 2,000-line hallucination problem and gives you checkpoints to verify quality.
