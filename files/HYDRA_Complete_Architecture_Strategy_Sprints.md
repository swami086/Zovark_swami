# HYDRA — Complete Architecture, Strategy & Sprint Plan
## CTO Reference Document — Carry Into Any Fresh Session

**Version:** 2.0
**Date:** March 8, 2026
**Author:** CTO (Claude) + CEO (Vinay)
**Classification:** CONFIDENTIAL

---

## PART 1: WHAT HYDRA IS

### The One-Liner

Hydra is the first sovereign autonomous SOC platform that investigates security alerts by writing and executing custom code — not running playbooks — and builds a compounding intelligence graph that gets smarter with every investigation and every client.

### Why It Exists

MSSPs (Managed Security Service Providers) are drowning. Tier-1 SOC analysts burn out in 18 months. The median MSSP handles 50-200 clients and cannot hire fast enough. 60-80% of SIEM alerts are duplicates or false positives that consume analyst time investigating the same thing repeatedly. Hydra autonomously handles L1 investigations at analyst quality, 24/7, without sending a single byte of data to the cloud.

### What Makes It Different (Competitive Moat)

Hydra has four structural advantages that no competitor can replicate without rebuilding from scratch:

**1. Investigation-as-Code (vs. Playbooks)**

Competitors (Dropzone AI, Prophet Security, Conifers.ai) teach LLMs to call pre-built API connectors. If a customer has a bespoke firewall, the vendor must build a connector. Hydra generates custom Python investigation code per alert, executes it in an ephemeral Docker sandbox, and extracts entities. The LLM IS the connector. Integration scale is infinite — limited by model capability, not engineering roadmap.

**2. Sovereign Entity Graph (vs. Cloud RAG)**

Competitors store text summaries in cloud-hosted RAG. Hydra builds a deterministic, typed entity graph with pgvector embeddings — 304 entities, 258 edges, 588 observations across 8 entity types. Cross-tenant correlation (29 entities seen across 2+ tenants) mathematically computes blast radius. Competitors' memory makes a chatbot sound smarter. Hydra's graph computes threat propagation.

**3. Zero-Egress Architecture (vs. SaaS-Only)**

All three apex competitors are SaaS-only. Dropzone routes data through AWS and LLM-as-a-service providers. Defense contractors, hospitals, banks, and government SOCs legally cannot send SIEM logs to AWS or through OpenAI's API (ITAR, HIPAA, PCI-DSS, national security law). Hydra's Docker sandbox (--network=none, seccomp profiles) and K8s air-gap overlays enable fully on-premise deployment with local LLMs via LiteLLM proxy. Hydra is the only architecture that can run on an air-gapped server rack.

**4. Detection Generation Flywheel (vs. Static Output)**

Competitors close the ticket and output a timeline. Hydra closes the ticket, then pattern_miner.py and sigma_generator.py mine the investigation corpus to automatically write new Sigma detection rules (14 rules, 100% TP rate). Every investigation makes future detection better. Competitors resolve alerts. Hydra resolves alerts AND writes the rule to catch the attacker earlier next time.

### The Competitive Landscape

| Capability | Conifers.ai | Dropzone AI | Prophet Security | Hydra |
|---|---|---|---|---|
| AI Investigation | Yes (API tools) | Yes (pre-trained agents) | Yes (autonomous triage) | Yes (code generation) |
| Investigation-as-Code | No (playbooks) | No (pre-trained) | No (playbooks) | YES — LLM writes code per alert |
| Cross-Tenant Intelligence | No | No | No | YES — 29 entities correlated across 3 tenants |
| Air-Gap / On-Premise | No (SaaS) | No (SaaS/AWS) | No (SaaS) | YES — K8s air-gap overlay, local LLM |
| Auto-Detection Generation | No | No | No | YES — Sigma rules from investigation patterns |
| Temporal Entity Graph | No | No | No | Planned (Month 3-4) |
| Shared Verdict Index | No | No | No | Planned (Month 5-6) |
| Federated Learning | No | No | No | Planned (Month 9-12, Series A thesis) |

**The Kill Line in Every Demo:** "Everything you just watched? Zero bytes left this machine. Ask Dropzone to do that."

---

## PART 2: CURRENT STATE (as of Sprint 4A, commit 8efdb4f)

### Architecture

```
Alert → Go API (8090) → Temporal Workflow Engine → Python Worker
                                                      ├→ LLM Code Generation (LiteLLM → OpenRouter/Gemini Flash)
                                                      ├→ Sandboxed Execution (Docker --network=none --read-only)
                                                      ├→ Entity Extraction (LLM + regex fallback)
                                                      ├→ Entity Graph (pgvector embeddings, cross-tenant correlation)
                                                      ├→ Blast Radius + FP Confidence Scoring
                                                      ├→ Incident Report (Markdown + PDF)
                                                      ├→ SOAR Playbook Auto-Trigger
                                                      └→ Self-Healing SRE Agent
```

### Services (10 containers)

| Service | Tech | Port | Purpose |
|---|---|---|---|
| postgres | pgvector/pgvector:pg16 | 5432 | Primary database with vector embeddings |
| pgbouncer | pgbouncer | 6432 | Connection pooling |
| redis | redis:7-alpine | 6379 | Rate limiting leases, caching |
| temporal | temporalio/auto-setup:1.24.2 | 7233 | Workflow orchestration |
| litellm | LiteLLM proxy | 4000 | LLM routing (currently all → Gemini Flash via OpenRouter) |
| embedding-server | TEI (nomic-embed-text-v1.5) | 80 | 768-dim text embeddings |
| api | Go (custom) | 8090 | REST API with JWT auth |
| worker | Python (custom) | — | Temporal worker (7 workflows, 56 activities) |
| dashboard | React | 3000 | Web UI (minimal — needs rewrite) |
| minio | MinIO | 9000 | Object storage (PDF reports) |

### Database (22 tables + 2 materialized views + 2 views, 14 migrations)

**Core:** tenants(3), users(~5), agent_tasks(~145), agent_task_steps(~500+), investigations(138), investigation_steps(~1000+), investigation_reports(~5)

**Entity Graph:** entities(304 — 8 types), entity_edges(258 — 9 types), entity_observations(588), mitre_techniques(691, 100% embedded), bootstrap_corpus(1,636)

**Intelligence:** cross_tenant_intel(materialized view, 29 multi-tenant entities), model_performance(materialized view)

**Detection & Response:** detection_candidates(14), detection_rules(14, 100% TP), response_playbooks(5), response_executions(2), response_integrations(0)

**Observability:** llm_call_log(~16), audit_events(~25), approval_requests(6), self_healing_events(0)

**Phase 2 (empty):** webhook_endpoints(0), webhook_deliveries(0), finetuning_jobs(0), model_registry(0), model_ab_tests(0), data_retention_policies(0)

### Codebase

**Worker:** 39 Python files, ~7,600 LOC
**API:** Go binary
**Dashboard:** React app

```
worker/
├── main.py                    # Entry point: 7 workflows, 56 activities
├── workflows.py               # ExecuteTaskWorkflow (main investigation pipeline)
├── activities.py              # Core activities: generate_code, execute_code, etc.
├── entity_graph.py            # Entity extraction + graph writing
├── entity_normalize.py        # IP/domain/hash normalization
├── redis_client.py            # Legacy INCR/DECR rate limiting
├── rate_limiter.py            # Lease-based rate limiting (replaces redis_client)
├── model_config.py            # 3-tier model routing (fast/standard/reasoning)
├── prompt_registry.py         # SHA256-based prompt version tracking
├── prompt_init.py             # Registers 10 prompts at startup
├── context_manager.py         # Model-aware context truncation
├── llm_logger.py              # Non-blocking LLM call logging
├── logger.py                  # Structured JSON logging
├── bootstrap/                 # BootstrapCorpusWorkflow + MITRE loading
├── detection/                 # pattern_miner, sigma_generator, rule_validator
├── response/                  # 7 action types, ResponsePlaybookWorkflow
├── intelligence/              # blast_radius, fp_analyzer, cross_tenant
├── reporting/                 # Markdown + PDF incident reports
├── security/                  # injection_detector, prompt_sanitizer
├── skills/                    # deobfuscation.py (code exists, but agent_skills table is EMPTY)
├── sre/                       # SelfHealingWorkflow (monitor, diagnose, patch, test, apply)
├── finetuning/                # FineTuningPipelineWorkflow (no data yet)
├── validation/                # [NEW IN SPRINT 5] dry_run.py
├── investigation_memory.py    # [NEW IN SPRINT 5]
└── prompts/
    ├── entity_extraction.py   # Entity extraction system prompt
    └── investigation_prompt.py # [NEW IN SPRINT 5]
```

### Temporal Workflows

| Workflow | Purpose | Trigger |
|---|---|---|
| ExecuteTaskWorkflow | Main investigation pipeline | API task submission |
| BootstrapCorpusWorkflow | Generate synthetic investigations from MITRE | Manual |
| CrossTenantRefreshWorkflow | Update cross-tenant intelligence views | Scheduled/manual |
| DetectionGenerationWorkflow | Mine patterns → generate Sigma rules → validate | Scheduled/manual |
| ResponsePlaybookWorkflow | Execute SOAR playbook actions with approval gates | Auto-triggered |
| SelfHealingWorkflow | Scan failures → diagnose → patch → test → apply | Scheduled/manual |
| FineTuningPipelineWorkflow | Export training data → score → evaluate | Manual |

### Model Configuration (3 tiers, currently all → Gemini Flash)

| Tier | Temp | Max Tokens | Activities |
|---|---|---|---|
| fast | 0.1 | 1,024 | extract_entities, fill_skill_parameters |
| standard | 0.3 | 4,096 | generate_code, generate_followup_code, generate_incident_report |
| reasoning | 0.2 | 4,096 | analyze_false_positive, generate_sigma_rule, diagnose_failure |

### What Works vs. What Doesn't

**Working:**
1. Alert → full investigation with code execution, entity extraction, risk scoring, incident report
2. Cross-tenant entity correlations and threat scores across 3 tenants
3. Auto-generate Sigma detection rules from investigation patterns (14 rules, 100% TP)
4. Auto-trigger SOAR playbooks based on verdict + risk score (5 playbooks, 7 action types)
5. Self-heal worker failures via SRE agent (dry-run verified)
6. Monitor via Prometheus + Grafana (3 dashboards, 6 alert rules)
7. Tenant onboarding via API + webhook configuration
8. Fine-tuning data export from LLM call logs
9. A/B test models via model registry

**Broken / Missing:**
1. Dashboard is minimal — no investigation view, no entity graph visualization, no reports
2. agent_skills table is empty (0 rows) — skill-based routing broken
3. No real webhook integrations — SOAR actions all simulated
4. Single model, no fallback — OpenRouter outage = total platform failure
5. No output validation beyond AST prefilter — garbage code flows downstream
6. No demo flow — prospects can't see the platform without CLI
7. No alert deduplication — 5,000 identical alerts = 5,000 separate investigations
8. No investigation memory — each investigation starts from scratch

### Completed Sprints (21 total)

Phase 1 MVP (13 sprints): Block 1.1-1.5, 1E, 1G, 1F, 1L, 1H, docs, 1K, 1I, 1J, 2A, 2B, Audit
Phase 2 Production (8 sprints): 3A, 3B, 3C, 3D, 3E, 3F, fix, RCA
Phase 3 Autonomous (1 sprint): 4A

---

## PART 3: STRATEGIC DECISIONS (CTO + CEO, agreed in this session)

### Features PAUSED (not deleted — stay in codebase, no new sprint effort)

| Feature | Rationale | Revisit When |
|---|---|---|
| MCP Server (Sprint 4C) | Developer convenience, not customer need | Post-PMF |
| Fine-Tuning Pipeline | 0 training data, need 10K+ examples | Month 6+ |
| Model A/B Testing | Framework built, 0 models to test | When 2+ models in production |
| Self-Healing SRE Agent | 0 production users to self-heal for | Post-pilot |
| SOAR Real Integrations | Cannot auto-execute until accuracy proven >90% | Month 3-4 |

### Features PRIORITIZED

| Feature | Sprint | Why |
|---|---|---|
| LLM Reliability Layer (fallback chains) | 5 (Days 1-3) | Single model = single point of failure |
| Dry-Run Validation Gate | 5 (Days 2-3) | Garbage code flows downstream unchecked |
| Skills Table Population | 5 (Days 3-4) | Core pipeline partially non-functional |
| Investigation Memory | 5 (Days 4-6) | Each investigation starts from scratch = wasted work |
| Dashboard Rewrite (3 views) | 5 (Days 8-12) | Cannot sell without visual demo |
| Integration Tests | 5 (Day 7) | Cannot guarantee golden path works |
| Alert Deduplication Layer 1 | 5 (Day 14) | 5,000 duplicate alerts = 5,000 investigations = melted LLM budget |
| Air-Gap LLM (Ollama/vLLM) | 6 (Weeks 5-6) | THE competitive differentiator — not deferred |
| SIEM Webhooks (Splunk + Sentinel) | 6 (Weeks 5-7) | Required for pilot |
| Tenant Self-Service Onboarding | 6 (Weeks 6-7) | Required for pilot |
| Usage Metering + Pricing | 6 (Weeks 7-8) | Required before sending first invoice |

### CTO Corrections (Apply in ALL implementation)

1. **Investigation Memory: TWO-PASS only.** Exact value match first (fast, high confidence), then pgvector semantic search (slower, clearly labeled "similar"). NO CIDR /24 normalization for IPs. Per-entity-type similarity thresholds, tunable, logged for calibration.

2. **JSON enforcement: NO response_format API parameter.** Providers handle it inconsistently. Enforce JSON structure in prompt text. Validate output via key checking in code.

3. **No SOAR real integrations in pilot.** Observation mode only. Existing 5 playbooks from Sprint 2B sufficient for demo. No CrowdStrike/Okta/PagerDuty API calls.

4. **All new worker code lives in worker/ directory.** NOT hydra/core/ or hydra/investigation/. Follow existing flat structure.

5. **All LLM calls MUST use existing conventions:** get_tier_config() + log_llm_call() + get_version() pattern.

6. **DryRunSandbox uses subprocess with resource limits.** NOT Docker-in-Docker (2-5s container startup overhead defeats the 5s budget).

7. **Entity similarity thresholds are per-type and configurable:**
   - ip: 0.15 | domain: 0.20 | file_hash: 0.10 | user: 0.25 | process: 0.20 | url: 0.20 | email: 0.20
   - Override via HYDRA_SIMILARITY_THRESHOLD env var

---

## PART 4: ALERT DEDUPLICATION ARCHITECTURE

### Why It's Critical

A mid-tier MSSP sees 5,000-15,000 alerts/day. 60-80% are duplicates. Without dedup, Hydra spins up a separate Temporal workflow (separate LLM calls, sandbox executions, entity extractions) for every single duplicate. This melts the LLM budget and pollutes the entity graph.

### Three-Layer Dedup Stack

**Layer 1 — Exact-Match Alert Fingerprinting (Sprint 5, Day 14)**

Algorithm: SHA-256 composite hash over normalized alert fields (tenant_id, alert_type, source_ip, dest_ip, rule_name). Time-windowed dedup (configurable per tenant, default 15 minutes). If fingerprint matches within window → increment counter on existing investigation. If no match → create new investigation.

Expected ratio: 8:1 to 10:1 (10,000 alerts → 1,000-1,250 investigations)

**Layer 2 — Near-Duplicate Fuzzy Matching (Sprint 6, Week 5)**

Algorithm: MinHash + Locality-Sensitive Hashing (LSH). Shingle alerts into semantic field tokens (source IP, source subnet, dest subnet, alert category, MITRE technique, time bucket). 128 MinHash functions, 16 bands of 8 rows (tuned for ~0.7 Jaccard threshold). Candidates verified by full Jaccard similarity. Uses datasketch Python library.

Expected additional ratio: 1.5:1 to 3:1 on top of Layer 1

**Layer 3 — Investigation Correlation via Entity Overlap (Sprint 6, Week 6)**

Algorithm: Weighted Jaccard on entity sets + pgvector cosine similarity. Post-extraction step in ExecuteTaskWorkflow checks entity overlap with recent investigations (same tenant, last 60 minutes). If overlap > 70% → link via related_investigations table, produce consolidated report.

Expected additional ratio: 1.2:1 to 1.5:1

**Combined ratio: 15:1 to 33:1** (10,000 daily alerts → 300-650 investigations)

### Schema

```sql
-- Migration 016: alert_fingerprints
CREATE TABLE alert_fingerprints (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id),
    fingerprint           VARCHAR(64) NOT NULL,
    alert_type            VARCHAR(100) NOT NULL,
    first_seen            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_count           INTEGER NOT NULL DEFAULT 1,
    investigation_id      UUID REFERENCES investigations(id),
    dedup_window_seconds  INTEGER NOT NULL DEFAULT 900,
    raw_sample            JSONB,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_alert_fp_tenant_hash
    ON alert_fingerprints(tenant_id, fingerprint)
    WHERE last_seen > NOW() - INTERVAL '24 hours';
```

---

## PART 5: THE PRODUCT HYDRA DELIVERS

Hydra is not a report generator. The PDF is the receipt, not the meal.

| Output | Format | Consumer | Value |
|---|---|---|---|
| Real-time Investigation State | WebSocket → Dashboard | SOC Analyst | Watch code generate, entities extract, graph build live |
| Entity Graph | PostgreSQL + pgvector + D3.js | Analyst + System | Persistent knowledge, cross-tenant intelligence |
| Verdict + Confidence | JSON via API | SOAR, SIEM, Ticket system | Automated response trigger (observation mode for pilot) |
| SOAR Actions (future) | API calls | Firewalls, EDR, Slack | Hands-free remediation (post-pilot, when accuracy >90%) |
| Detection Rules | Sigma format | SIEM | Alert generation from investigation patterns |
| Investigation Report | Markdown → PDF | Managers, Compliance, Clients | Human-readable summary (the receipt) |

### The Product Flow

```
SIEM Alert ──→ Hydra API ──→ Dedup Check (Layer 1)
                                  │
                    [Duplicate? → Increment counter, skip]
                    [New? → Continue ↓]
                                  │
                    Investigation Memory Check (Step 0)
                    "Seen this IP before → Malicious C2"
                                  │
                    Generate Python Code ──► LiteLLM (w/ fallback chain)
                                  │
                    Dry-Run Validate (5s sandbox gate)
                                  │
                    Full Sandbox Execution (30s, --network=none)
                                  │
                    Entity Extraction ──► Entity Graph + Memory
                                  │
                    ┌─────────────┼──────────────┐
                    ▼             ▼              ▼
              Dashboard      Verdict JSON      Report
              (Real-time)    (→ SOAR future)   (PDF)
```

---

## PART 6: SPRINT 5 — THE 14-DAY EXECUTION PLAN

### Summary

| Day | Task | Deliverable | Verification |
|---|---|---|---|
| 1 | LiteLLM fallback config | litellm_config.yaml with 3 tiers, fallback chains | docker compose up litellm → logs show all models |
| 2-3 | Dry-run validation gate | worker/validation/dry_run.py wired into activities.py | Bad code → rejected; good code → passes |
| 3-4 | Migration 015: Skills seed | 5 skills in agent_skills table | SELECT count(*) FROM agent_skills = 5 |
| 4-5 | Investigation Memory | worker/investigation_memory.py with two-pass matching | Submit known IOC → prior conclusion returned |
| 5-6 | Wire Memory into workflow | Step 0 enrichment in ExecuteTaskWorkflow | Full workflow runs with memory context in prompt |
| 7 | Integration tests | tests/integration/test_sprint5.py (10 tests) | pytest green |
| 8-10 | Dashboard: Investigation waterfall | WebSocket real-time step rendering | Watch investigation execute live in browser |
| 11-12 | Dashboard: Entity graph + report | D3.js force-directed graph, Markdown viewer + PDF export | Click entity → see prior investigations |
| 13 | Demo scenarios | 3 pre-loaded alerts, /demo route | Non-technical person runs demo unassisted |
| 14 | Dedup Layer 1 | Migration 016: alert_fingerprints, SHA-256 in Go API | 100 duplicate alerts → 1 investigation, alert_count=100 |

### The Claude Code Prompt

The complete, CTO-corrected Claude Code prompt is in a separate file:
**HYDRA_Sprint5_ClaudeCode_Prompt_CORRECTED.md**

That file contains every file to create/modify, exact code, verification commands, and the 11 errata corrections from the original Brainiac prompt.

---

## PART 7: SPRINT 6 — WEEKS 5-8 (post Sprint 5)

### Sprint 6A: Air-Gap LLM + SIEM Webhooks (Weeks 5-6)

**Air-Gap (THE competitive differentiator):**
- Integrate Ollama/vLLM as a LiteLLM provider for local model inference
- Add to litellm_config.yaml as lowest-priority fallback (becomes primary in air-gap mode)
- Test full investigation pipeline with local model only (no internet)
- Update K8s air-gap overlay to include local model container
- Demo: run entire investigation on laptop with wifi off

**SIEM Webhooks:**
- Inbound webhook receivers for Splunk and Microsoft Sentinel (~70% MSSP market)
- Alert normalization layer → maps SIEM-specific fields to Hydra's alert schema
- Outbound webhooks: Slack, PagerDuty, email (wire existing webhook_endpoints/deliveries tables)

### Sprint 6B: Onboarding + Metering + Dedup L2 (Weeks 6-7)

**Tenant Self-Service:**
- Dashboard flow: create tenant → configure SIEM webhook → set notification channels → run test investigation
- Wraps existing Tenant CRUD API from Sprint 3C in UI

**Usage Metering:**
- Investigation counting per tenant, LLM token tracking, sandbox compute tracking
- Usage dashboard for MSSP admin showing per-client costs
- Dedup ratio display: "Hydra saved you from N redundant investigations this week"

**Dedup Layer 2:**
- MinHash + LSH implementation using datasketch library
- Migration 017: alert_minhash_signatures table
- Wire into ingest path after Layer 1

### Sprint 6C: Pilot Prep (Week 8)

- Staging environment with monitoring and runbook
- Load test: survive 100 test alerts without failure
- Pilot contract template with 30-day structured feedback loop
- Demo script with competitive kill slides

---

## PART 8: SPRINT 7 — WEEKS 9-12 (First Customer)

### Sprint 7A: Pilot Launch (Week 9)

- First MSSP connected, real SIEM alerts flowing
- Real analysts comparing Hydra output to their own investigations
- Real webhook notifications going to real Slack channels
- Daily monitoring of investigation quality metrics

### Sprint 7B: Pilot Iteration (Weeks 10-11)

- Bug fixes, prompt tuning, quality improvements
- Target: >70% investigation accuracy vs. L1 analyst
- Entity graph calibration with real-world data
- Similarity threshold tuning based on logged distances

### Sprint 7C: Pilot Review + Conversion (Week 12)

- Go/no-go decision with structured scoring
- Conversion to 12-month annual contract
- Target: ₹1L/month MRR

---

## PART 9: MONTH 3-12 ROADMAP (Post-Pilot)

| Month | Capability | Customer Value | Technical Complexity |
|---|---|---|---|
| 3-4 | Temporal Entity Graph | "This IP appeared 3 hours before ransomware in 4 prior cases" | Medium — timestamp edges + sequence mining on existing graph |
| 3-4 | SOAR Real Integrations (post accuracy >90%) | Auto-isolate host, block IP, disable user with approval gates | Medium — wire existing playbooks to CrowdStrike/Okta APIs |
| 5-6 | Shared Verdict Index | "When Client A finds a threat, Client B knows in seconds" | Low — API endpoint + anonymized verdict database |
| 5-6 | Temporal Pattern Sharing | "Attack chain at Client A predicted at Client B" | Medium — attack chain fingerprinting |
| 5-6 | Network-Effect Pricing | Volume discounts incentivize full-book deployment | Business — pricing model change |
| 6-8 | Heartbeat Threat Hunting | Proactive 24/7 hunting via declarative beat files | Low — Temporal CronSchedule + synthetic alerts |
| 6-8 | Sub-Investigation Parallelism | Multi-vector investigations via child workflows | Medium — Temporal child workflows + result merging |
| 9-12 | Federated Learning + Differential Privacy | Each client's model improves from entire network | Very High — Series A thesis, dedicated ML engineer |

### Network-Effect Pricing (Month 5-6)

| Deployment | Price per Client |
|---|---|
| Single client | ₹1L/month |
| 10+ clients | ₹75K/month (25% discount) |
| 50+ clients | ₹50K/month (volume + network value) |

Pitch: "You're not buying software. You're joining an intelligence network. The more clients in the network, the cheaper it gets — because each one makes the others more valuable."

---

## PART 10: UNICORN TRAJECTORY

| Horizon | Revenue | Customers | Key Milestone |
|---|---|---|---|
| Month 3 | ₹1L MRR | 1 pilot | Prove investigation quality on real alerts |
| Month 6 | ₹5L MRR | 3-5 MSSPs | Repeatable onboarding + sales motion |
| Month 12 | ₹30L MRR | 15-20 MSSPs | Seed round ($1-2M) or profitability |
| Month 24 | $500K MRR | 50+ MSSPs | Series A ($10-15M) at $80-100M valuation |
| Month 48 | $5M MRR | 200+ MSSPs + enterprise direct | Series B, $500M+ valuation, unicorn path |

### 90-Day Success Metrics

| Metric | Target | Measurement |
|---|---|---|
| Paying customers | ≥1 | Signed contract + first invoice |
| MRR | ≥₹1,00,000 | Cash received |
| Investigation accuracy vs. L1 analyst | ≥70% | Blind comparison on 50 real alerts |
| Golden path success rate | ≥95% | Alert → report without human intervention |
| Demo-to-pilot conversion | ≥10% | Demos given → pilots signed |

### Two Target Segments (Parallel Pursuit)

**Segment A — MSSP Pilot (Volume Play):**
Mid-tier Indian MSSP, 20-50 clients, Splunk or Sentinel, 4-8 SOC analysts, founder-led. Pitch: "Run Hydra alongside your L1 analysts for 30 days. If it closes 30% of alerts at analyst quality, it pays for itself in the first week." Price: ₹1L/month for up to 5 tenants.

**Segment B — Sovereign/Regulated Enterprise (Value Play):**
Defense contractors, banks, hospitals, government SOCs. Pitch: "Autonomous SOC investigations where no data leaves your perimeter. Your competitors legally cannot offer this." Price: 10-50x MSSP pricing. One defense contract at $200K/year = 20 MSSP pilots.

Pursue both in parallel: MSSP pilot for proof-of-quality, 3-5 regulated enterprise conversations for big deal pipeline.

---

## PART 11: RISK REGISTER

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|
| LLM output quality insufficient for real alerts | HIGH | CRITICAL | Multi-model fallback, dry-run gate, human-in-loop for first 100 investigations | CTO |
| No MSSP signs pilot within 90 days | MEDIUM | HIGH | Start outreach at Week 4. Target 10 conversations → 1 pilot. Leverage network. | CEO |
| Dashboard sprint takes >2 weeks | HIGH | MEDIUM | Scope: 3 views only. No settings, admin panel, or user management in V1. | CTO |
| OpenRouter rate limits during demo | MEDIUM | HIGH | Cache demo results. Pre-run scenarios, replay via WebSocket. | CTO |
| Founder bandwidth split (Hydra/RoamStack/property) | HIGH | CRITICAL | Hydra 80% for 90 days. RoamStack maintenance mode. Property sale delegated to broker. | CEO |
| False positive auto-executes during pilot | MEDIUM | CRITICAL | Observation mode only for pilot. No auto-response until accuracy >90% proven. | CTO |

---

## PART 12: CONVENTIONS & OPERATIONS

### Development Conventions

- **Windows host, no Python on host** — all Python runs in Docker containers
- **Semicolons not &&** for bash command chaining
- **Postgres access:** `docker compose exec -T postgres psql -U hydra -d hydra`
- **Worker access:** `docker compose exec -T worker python -c "..."`
- **Migrations:** Sequential numbering (001-014 done, next is 015), applied via `cat file.sql | docker exec -i hydra-postgres psql -U hydra -d hydra`
- **Line endings:** LF enforced via .gitattributes
- **Linting:** flake8 with `--max-line-length=200 --ignore=E501,W503,E402`
- **Temporal workflows:** Use `workflow.unsafe.imports_passed_through()` for non-deterministic imports
- **LLM calls:** ALWAYS use `get_tier_config()` + `log_llm_call()` + `get_version()` pattern
- **Protected files (NEVER modify):** sandbox/ast_prefilter.py, sandbox/seccomp_profile.json, sandbox/kill_timer.py
- **All new worker code** goes in `worker/` directory (NOT hydra/core/ or hydra/investigation/)

### Operating Hydra

```bash
# Start everything
cd C:\Users\vinay\Desktop\HYDRA\hydra-mvp
docker compose up -d

# Submit an investigation
TENANT_ID=$(docker compose exec -T postgres psql -U hydra -d hydra -t -c "SELECT id FROM tenants WHERE slug='hydra-dev'" | tr -d ' \n\r')
curl -s -X POST http://localhost:8090/api/v1/auth/register -H "Content-Type: application/json" -d "{\"email\":\"test@hydra.dev\",\"password\":\"testpass123\",\"display_name\":\"Test\",\"tenant_id\":\"$TENANT_ID\"}"
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"test@hydra.dev","password":"testpass123"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
curl -s -X POST http://localhost:8090/api/v1/tasks -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"task_type":"brute_force","input":{"prompt":"Investigate failed SSH login attempts from 203.0.113.50"}}'

# Health check
curl -s http://localhost:8090/api/v1/health
docker compose logs worker --tail 5
```

---

## PART 13: KEY FILES REFERENCE

| File | Purpose | Status |
|---|---|---|
| litellm_config.yaml | LLM routing with fallback chains | MODIFY in Sprint 5 Day 1 |
| docker-compose.yml | 10 services | MODIFY in Sprint 5 Day 1 (update litellm env vars) |
| worker/model_config.py | 3-tier model routing | MODIFY to point to new LiteLLM model names |
| worker/workflows.py | ExecuteTaskWorkflow | MODIFY to add Step 0 (memory) + dry-run gate |
| worker/activities.py | Core activities | MODIFY to add validate_generated_code + enrich_alert_with_memory |
| worker/validation/dry_run.py | 5-second dry-run sandbox gate | CREATE in Sprint 5 Days 2-3 |
| worker/investigation_memory.py | Two-pass entity memory enrichment | CREATE in Sprint 5 Days 4-5 |
| worker/prompts/investigation_prompt.py | Prompt template with memory injection | CREATE in Sprint 5 Days 4-5 |
| migrations/015_seed_agent_skills.sql | Seed 5 investigation skills | CREATE in Sprint 5 Days 3-4 |
| migrations/016_alert_fingerprints.sql | Alert dedup fingerprint table | CREATE in Sprint 5 Day 14 |
| tests/integration/test_sprint5.py | 10 integration tests | CREATE in Sprint 5 Day 7 |
| demo/scenarios.json | 3 pre-loaded demo scenarios | CREATE in Sprint 5 Day 13 |

---

**END OF DOCUMENT. The corrected Claude Code execution prompt is in the separate file: HYDRA_Sprint5_ClaudeCode_Prompt_CORRECTED.md**
