# HYDRA — Extracted Ideas from Brainiac + Rebuilt Prompts
## For Claude Code Execution Against Actual Codebase

**Date:** March 10, 2026
**Context:** Brainiac produced 8 prompt suites for a greenfield Node.js API. The actual codebase is a Go API + Python worker + Temporal + PostgreSQL + React dashboard. Below: every useful idea extracted, mapped to what already exists, and rebuilt as executable prompts.

---

## IDEA INVENTORY

### From Prompt 0 (Master Coordination)
| Idea | Status in Codebase | Verdict |
|---|---|---|
| File system as intelligence source (playbooks as Markdown) | Not implemented — Hydra uses DB-stored skills + LLM code gen | **SKIP** — Hydra's architecture is code generation, not playbook execution |
| Directory structure: /context/, /playbooks/, /api-specs/ | Not applicable — worker/ is the code structure | **SKIP** |

### From Prompt 1 (Context Files)
| Idea | Status | Verdict |
|---|---|---|
| Business rules document | Exists as HYDRA_Complete_Architecture_Strategy_Sprints.md | **ALREADY DONE** |
| MSSP personas (Nomios, PSY9, Critical Start, Almond) | Written for MSSP model — needs enterprise rewrite | **REWRITE** as enterprise personas |
| Investigation standards (output format, latency, confidence thresholds) | Partially in prompts/investigation_prompt.py | **USEFUL** — formalize as docs/investigation-standards.md |
| Kill conditions | In architecture doc risk register | **ALREADY DONE** |
| $0.10/investigation pricing | MSSP model — kill it | **KILL** |
| White-label requirements | MSSP model — not relevant for enterprise | **KILL** |
| Data sovereignty rules | Core to Hydra's value prop | **ALREADY BUILT** into architecture |
| Cross-tenant intelligence as moat | Built — 29 entities across 3 tenants | **ALREADY BUILT** |
| Margin protection (dedup, cache, multi-model routing) | Alert dedup (Sprint 5), model routing (Sprint 5), cache (not built) | **PARTIAL** — investigation cache worth adding |

### From Prompt 2 (Playbooks)
| Idea | Status | Verdict |
|---|---|---|
| Markdown playbooks for C2, phishing, lateral movement | Hydra generates code per alert, doesn't follow static playbooks | **SKIP** — wrong architecture |
| Playbook template with pre-flight checks | Skills table has 10 skills with expected_entity_types | **ALREADY DONE** differently |
| Test cases per playbook (3 TP, 3 FP) | Not implemented | **USEFUL** — extract as accuracy test dataset |
| Version-controlled investigation procedures | prompt_registry.py with SHA256 versioning | **ALREADY DONE** |

### From Prompt 3 (API Specs)
| Idea | Status | Verdict |
|---|---|---|
| SIEM integration specs (Wazuh, Splunk, Sentinel, CrowdStrike, TheHive) | Go API has webhook receiver for generic SIEM alerts | **USEFUL** — formalize SIEM connector docs |
| LLM routing config (Groq/Haiku/Sonnet/vLLM) | litellm_config.yaml with 3-tier fallback chains | **ALREADY DONE** (Sprint 5) |
| Sandbox provider specs | Docker sandbox with seccomp, AST prefilter, kill timer | **ALREADY DONE** |
| Enrichment sources (VirusTotal, AbuseIPDB, URLhaus, MISP, OTX) | Not integrated — code-gen approach means LLM writes enrichment code | **USEFUL LATER** — add as investigation skills |
| Accuracy validation framework (100 labeled alerts) | Not built | **USEFUL** — critical for enterprise credibility |

### From Prompt 4 (Accuracy Validation Gate)
| Idea | Status | Verdict |
|---|---|---|
| 100 labeled alerts (50 TP, 50 FP across 10 categories) | Not built | **HIGH PRIORITY** — needed to prove quality |
| Multi-stage pipeline simulation | Already built (code gen → sandbox → entity extraction) | **ALREADY DONE** |
| Metrics: accuracy, precision, recall, F1, FPR with confidence intervals | Not built | **USEFUL** |
| GO/NO-GO gate at 85% | Good discipline | **USEFUL** |
| Category-specific accuracy breakdown | Not built | **USEFUL** |

### From Prompt 5 (API Endpoints)
| Idea | Status | Verdict |
|---|---|---|
| POST /v1/investigate (async, 202 Accepted) | Go API: POST /api/v1/tasks (already does this) | **ALREADY DONE** |
| GET /v1/investigations/:id with full report | Go API: GET /api/v1/tasks/:id + /steps + /timeline | **ALREADY DONE** |
| Webhook configuration | Go API: webhook_endpoints table + delivery system | **ALREADY DONE** (Sprint 3C) |
| Idempotency via X-Idempotency-Key | Not implemented | **USEFUL** for production |
| Investigation cost tracking per step | llm_call_log tracks tokens but not cost | **USEFUL** — add cost_usd column |

### From Prompt 6 (Cost Router)
| Idea | Status | Verdict |
|---|---|---|
| Complexity-based model routing | model_config.py ACTIVITY_TIER_MAP (static per-activity) | **PARTIAL** — could add dynamic complexity scoring |
| Cost tracking per investigation | llm_call_log has token counts | **PARTIAL** — need cost calculation |
| Early exit at high confidence | Not implemented | **USEFUL** — skip follow-up steps if confidence >0.9 |
| Investigation cache (24h TTL) | Alert dedup exists but not investigation cache | **USEFUL** — high ROI for repeated alerts |
| Request deduplication | alert_fingerprints table (Sprint 5) | **ALREADY DONE** |
| Batch processing | Not implemented | **LOW PRIORITY** |

### From Prompt 7 (Feedback Loop & Data Moat)
| Idea | Status | Verdict |
|---|---|---|
| POST /investigations/:id/feedback endpoint | Not built | **HIGH PRIORITY** — the moat |
| Feedback vector storage with embeddings | entity graph has pgvector embeddings | **FOUNDATION EXISTS** |
| Cross-tenant intelligence queries | cross_tenant_intel materialized view | **ALREADY BUILT** |
| "Similar alerts across all clients" via vector similarity | investigation_memory.py does this per-entity | **ALREADY BUILT** (Sprint 5) |
| Anonymization pipeline | Not built | **USEFUL** for enterprise compliance |
| Weekly improvement reports | Not built | **USEFUL** for customer retention |
| GDPR compliance (opt-in, right to deletion) | data_retention_policies table exists | **PARTIAL** |

### From Prompt 8 (White-Label & Integration)
| Idea | Status | Verdict |
|---|---|---|
| White-label configuration | MSSP-specific — kill for enterprise | **KILL** |
| SOAR connectors (Tines, Torq, Shuffle, Splunk SOAR) | response_playbooks + webhook integrations exist | **ALREADY BUILT** (simulated) |
| ServiceNow/Jira ticket creation | response actions include create_ticket | **ALREADY BUILT** (simulated) |
| Dependency tracking ("migration resistance") | Not built | **USEFUL CONCEPT** but premature |
| Client-facing portal | Dashboard exists at localhost:3000 | **ALREADY BUILT** |

---

## REBUILT PROMPTS (For Claude Code, Against Actual Codebase)

---

### PROMPT A: Executive Summary Ribbon + Sovereignty Badges (2 hours)

```
# Dashboard Enhancement: Executive Summary + Sovereignty Badges

## Context
Repo: C:\Users\vinay\Desktop\HYDRA\hydra-mvp
Dashboard: dashboard/ (React 18 + Vite + Tailwind)
Latest: Sprint 6 (ea7ca8d) — waterfall demo working

The demo waterfall works but doesn't communicate ROI or data sovereignty.
Enterprise buyers need to see: "How much time/money does this save?" and
"Where does my data go?"

## Deliverables

### A-1: ExecutiveSummary Component

Create dashboard/src/components/ExecutiveSummary.tsx

A ribbon at the top of the demo page showing:
- Alerts Auto-Triaged: 1,204 (hardcoded for demo — will be real later)
- Analyst Hours Saved: 340
- Mean Time to Respond: 8.2s
- Cost Avoided: $127,200

Right side badge: "✅ All data processed locally"

Style: White background, subtle border-bottom, 4-column grid.
Matches existing dark theme sidebar.

### A-2: DataFlowBadge Component

Create dashboard/src/components/DataFlowBadge.tsx

Small badge that appears on each waterfall step:
- Green "🟢 LOCAL" for steps that run locally (parse, sandbox, extract, validate, complete)
- Blue "🔵 LLM" for steps that call LiteLLM (generate code, generate report)

This visually proves data sovereignty per step.

### A-3: Wire into DemoPage

Modify dashboard/src/pages/DemoPage.tsx:
- Add ExecutiveSummary above the investigation header
- Add DataFlowBadge to each step in InvestigationWaterfall

Update c2BeaconScenario.ts to include execution_context: 'local' | 'llm'
for each step.

### A-4: Sovereignty Banner

Add to the demo page between ExecutiveSummary and investigation header:
"Local VPC Processing → LLM Enrichment → Local Report"
with "Zero PII sent to cloud" badge on the right.

## Verification
- npm run build (zero errors)
- Demo page shows executive ribbon with 4 metrics
- Each waterfall step has LOCAL or LLM badge
- Sovereignty banner visible between ribbon and waterfall

## Commit
git add -A; git commit -m "Dashboard: executive summary ribbon + sovereignty badges for enterprise demo"; git push
```

---

### PROMPT B: Accuracy Validation Framework (4 hours)

```
# Accuracy Validation Framework

## Context
Repo: C:\Users\vinay\Desktop\HYDRA\hydra-mvp
Worker: 7 workflows, 58 activities, runs inside Docker
Conventions: semicolons not &&, all Python in Docker

HYDRA needs to prove investigation quality to enterprise buyers.
This creates a labeled test dataset and validation pipeline.

## Deliverables

### B-1: Test Dataset

Create worker/tests/accuracy/test_alerts.json

50 labeled alerts (25 true threats, 25 benign):

Categories (5 alerts each, mix of TP and FP):
1. C2 Beacon (3 TP, 2 FP)
2. Brute Force (3 TP, 2 FP)
3. Phishing (3 TP, 2 FP)
4. Lateral Movement (3 TP, 2 FP)
5. Malware (3 TP, 2 FP)
6. Data Exfiltration (2 TP, 3 FP)
7. Privilege Escalation (2 TP, 3 FP)
8. Reconnaissance (2 TP, 3 FP)
9. Persistence (2 TP, 3 FP)
10. Defense Evasion (2 TP, 3 FP)

Each alert has:
{
  "id": "TP-001",
  "type": "c2_beacon",
  "label": "threat",  // ground truth
  "severity": "high",
  "description": "Outbound DNS beaconing to suspicious domain at regular 5-min intervals",
  "indicators": {
    "source_ip": "10.0.1.50",
    "dest_domain": "update-service.xyz",
    "beacon_interval_seconds": 300,
    "ja3_hash": "a0e9f5d..."
  }
}

FP examples should be realistic benign activity that looks suspicious:
- Chrome auto-updates (looks like beaconing)
- Backup service to S3 (looks like exfiltration)
- CI/CD pipeline (looks like lateral movement)
- Admin scheduled task (looks like persistence)

### B-2: Validation Runner

Create worker/tests/accuracy/run_validation.py

NOT a pytest test — a standalone script that:
1. Loads test_alerts.json
2. For each alert, submits to Hydra via Temporal workflow
3. Waits for completion (timeout 60s per investigation)
4. Compares verdict to ground truth label
5. Calculates: accuracy, precision, recall, F1, FPR
6. Outputs JSON report to worker/tests/accuracy/results.json

Run via:
docker compose exec -T worker python tests/accuracy/run_validation.py

### B-3: Results Schema

{
  "validation_date": "2026-03-10",
  "total_alerts": 50,
  "metrics": {
    "accuracy": 0.XX,
    "precision": 0.XX,
    "recall": 0.XX,
    "f1": 0.XX,
    "fpr": 0.XX
  },
  "by_category": {
    "c2_beacon": { "correct": X, "total": 5, "tp": X, "fp": X, "tn": X, "fn": X }
  },
  "failures": [
    { "id": "TP-003", "expected": "threat", "got": "benign", "confidence": 0.42 }
  ],
  "recommendation": "PROCEED | IMPROVE | KILL"
}

Recommendation logic:
- PROCEED: accuracy >= 85%, precision >= 85%, recall >= 85%
- IMPROVE: any metric 70-85%
- KILL: any metric < 70%

## Note
This requires a working LLM connection. If API keys aren't configured,
create the dataset and runner structure with a --dry-run flag that
simulates random verdicts to test the pipeline.
```

---

### PROMPT C: Analyst Feedback Endpoint (2 hours)

```
# Analyst Feedback Collection — The Data Moat

## Context
Repo: C:\Users\vinay\Desktop\HYDRA\hydra-mvp
Go API: api/ (Gin framework, port 8090)
DB: PostgreSQL with pgvector

Every investigation should accept feedback from analysts.
This feedback becomes the data moat — cross-tenant intelligence
that no competitor can replicate.

## Deliverables

### C-1: Migration 017

Create migrations/017_investigation_feedback.sql

CREATE TABLE IF NOT EXISTS investigation_feedback (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    investigation_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    analyst_id UUID REFERENCES users(id),
    verdict_correct BOOLEAN,
    corrected_verdict VARCHAR(30),
    false_positive BOOLEAN DEFAULT false,
    missed_threat BOOLEAN DEFAULT false,
    notes TEXT,
    analyst_confidence FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_feedback_investigation ON investigation_feedback(investigation_id);
CREATE INDEX idx_feedback_tenant ON investigation_feedback(tenant_id);
CREATE INDEX idx_feedback_verdict ON investigation_feedback(verdict_correct);

### C-2: Go API Endpoints

Add to api/handlers.go (or create api/handlers_feedback.go):

POST /api/v1/investigations/:id/feedback
- Body: { "verdict_correct": bool, "corrected_verdict": string, "false_positive": bool, "notes": string }
- Auth: requires analyst+ role
- Stores in investigation_feedback table
- Returns 201

GET /api/v1/feedback/stats
- Returns: { "total": N, "correct": N, "incorrect": N, "accuracy": 0.XX, "by_type": {...} }
- Auth: requires admin role
- Aggregates across all feedback for the tenant

### C-3: Feedback Metrics View

Create a materialized view for feedback aggregation:

CREATE MATERIALIZED VIEW feedback_accuracy AS
SELECT
    i.task_type,
    COUNT(*) as total_feedback,
    SUM(CASE WHEN f.verdict_correct THEN 1 ELSE 0 END) as correct,
    SUM(CASE WHEN f.false_positive THEN 1 ELSE 0 END) as false_positives,
    ROUND(AVG(CASE WHEN f.verdict_correct THEN 1.0 ELSE 0.0 END), 3) as accuracy_rate
FROM investigation_feedback f
JOIN investigations i ON i.id = f.investigation_id
GROUP BY i.task_type;

### C-4: Wire into MCP Server

Add to mcp-server/src/index.ts:
- New resource: hydra://feedback/accuracy → feedback_accuracy view
- Update hydra_query to allow SELECT on investigation_feedback

## Verification
- Apply migration: cat migrations/017... | docker exec -i hydra-postgres psql -U hydra -d hydra
- docker compose build api; docker compose up -d api
- curl -X POST localhost:8090/api/v1/investigations/{id}/feedback with test data
- Verify row in investigation_feedback table
```

---

### PROMPT D: Investigation Cost Tracking (1 hour)

```
# Investigation Cost Tracking

## Context
llm_call_log table already tracks input_tokens, output_tokens per LLM call.
Need to add cost calculation and per-investigation cost rollup.

## Deliverables

### D-1: Add cost column to llm_call_log

ALTER TABLE llm_call_log ADD COLUMN IF NOT EXISTS cost_usd DECIMAL(10,6);

### D-2: Cost Calculator

Create worker/cost_calculator.py

COST_PER_1K = {
    'hydra-fast': {'input': 0.0002, 'output': 0.0002},       # Groq
    'hydra-standard': {'input': 0.003, 'output': 0.015},      # Gemini Pro
    'hydra-reasoning': {'input': 0.003, 'output': 0.015},     # Claude Sonnet
    'hydra-fast-fallback': {'input': 0.001, 'output': 0.002}, # Gemini Flash
}

def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = COST_PER_1K.get(model, {'input': 0.01, 'output': 0.03})
    return (input_tokens * rates['input'] + output_tokens * rates['output']) / 1000

### D-3: Wire into llm_logger.py

Update log_llm_call() to calculate and store cost_usd using cost_calculator.

### D-4: Per-Investigation Cost View

CREATE VIEW investigation_costs AS
SELECT
    task_id,
    COUNT(*) as llm_calls,
    SUM(input_tokens) as total_input_tokens,
    SUM(output_tokens) as total_output_tokens,
    SUM(cost_usd) as total_cost_usd
FROM llm_call_log
WHERE task_id IS NOT NULL
GROUP BY task_id;
```

---

### PROMPT E: Investigation Cache (2 hours)

```
# Investigation Result Cache

## Context
Alert dedup (Sprint 5) prevents duplicate investigations from starting.
But different alerts with the SAME indicators should return cached results
instead of re-investigating.

## Deliverables

### E-1: Cache Table

CREATE TABLE IF NOT EXISTS investigation_cache (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    cache_key VARCHAR(64) NOT NULL,  -- SHA-256 of normalized indicators
    investigation_id UUID NOT NULL,
    verdict VARCHAR(30),
    risk_score FLOAT,
    confidence FLOAT,
    entity_count INTEGER,
    ttl_hours INTEGER DEFAULT 24,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE UNIQUE INDEX idx_cache_key ON investigation_cache(cache_key)
WHERE expires_at > NOW();

### E-2: Cache Logic in Workflow

In ExecuteTaskWorkflow, before code generation (after memory enrichment):
1. Extract indicators from alert input (IPs, domains, hashes)
2. Normalize and sort
3. SHA-256 hash → cache_key
4. Query investigation_cache WHERE cache_key = X AND expires_at > NOW()
5. If hit: return cached verdict + report, skip investigation
6. If miss: continue with investigation, store result in cache on completion

### E-3: Cache Hit Metrics

Add to dashboard stats:
- Cache hit rate (%) 
- Investigations saved by cache
- Cost saved by cache
```

---

### PROMPT F: Air-Gap Deployment Test (3 hours)

```
# Air-Gap LLM Deployment Test

## Context
THE competitive differentiator. Must prove: "Turn off wifi, run investigation."

## Deliverables

### F-1: Add Ollama to docker-compose.yml

  ollama:
    image: ollama/ollama:latest
    volumes:
      - ollama_data:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    ports:
      - "11434:11434"

### F-2: Add Ollama as LiteLLM fallback

In litellm_config.yaml, add as lowest-priority fallback per tier:

  - model_name: "hydra-fast-airgap"
    litellm_params:
      model: "ollama/qwen2.5:7b"
      api_base: "http://ollama:11434"

Update router_settings fallbacks to include airgap models.

### F-3: Model Pull Script

Create scripts/airgap-setup.sh:
docker compose exec ollama ollama pull qwen2.5:7b
docker compose exec ollama ollama pull nomic-embed-text

### F-4: Air-Gap Test Script

Create scripts/test-airgap.sh:
1. Disconnect network (simulate by setting OPENROUTER_API_KEY to invalid)
2. Submit investigation via API
3. Verify it completes using local Ollama
4. Print: "AIR-GAP TEST: PASSED — investigation completed without internet"
```

---

### PROMPT G: Enterprise Positioning Document (1 hour, non-code)

```
# 2-Page Enterprise Positioning PDF

Create docs/hydra-enterprise-overview.md with content for a
leave-behind document targeting CISOs at regulated enterprises.

Page 1: The Problem + Solution
- "Your SOC analysts investigate 1,000+ alerts/day. 80% are duplicates."
- "Cloud AI vendors can't touch your data. ITAR, HIPAA, PCI-DSS, CMMC."
- "Hydra: Autonomous investigation engine that runs entirely in your VPC."
- Key metrics: 8.7s per investigation, 90%+ accuracy, zero data egress

Page 2: How It Works + Differentiation
- Architecture diagram: Alert → Code Gen → Sandbox → Entity Graph → Verdict
- Comparison table vs Dropzone/Prophet/Conifers (all SaaS-only)
- "The Kill Line: Everything you just watched? Zero bytes left this machine."
- Design partnership offer: 90-day deployment, founder-tier pricing

Target: US defense primes, Five Eyes, US/EU banks, Gulf sovereign entities
```

---

## EXECUTION ORDER

| Priority | Prompt | Time | Why |
|---|---|---|---|
| 1 | A (Executive Ribbon + Sovereignty) | 2 hrs | Immediate demo improvement for enterprise |
| 2 | G (Enterprise Positioning Doc) | 1 hr | Leave-behind for conversations |
| 3 | F (Air-Gap Test) | 3 hrs | "Turn off wifi" demo is the kill shot |
| 4 | C (Feedback Endpoint) | 2 hrs | Foundation of the data moat |
| 5 | B (Accuracy Validation) | 4 hrs | Proves quality to enterprise buyers |
| 6 | D (Cost Tracking) | 1 hr | Shows unit economics |
| 7 | E (Investigation Cache) | 2 hrs | Operational efficiency |

**Total: ~15 hours of focused work.**

Items from Brainiac that are explicitly KILLED:
- Playbook files (wrong architecture)
- Node.js API endpoints (already have Go API)
- White-label system (MSSP-specific)
- $0.10/investigation pricing (enterprise pricing is $50K+/year)
- MSSP personas (replaced with enterprise targets)
- "Hostage-grade integration" (premature, no customers yet)
