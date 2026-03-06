# HYDRA Sprint 1H — Bootstrap Pipeline (Cold Start Solver)
## Claude Code Prompt

---

You are building Sprint 1H for HYDRA, an AI-powered SOC investigation automation platform. This sprint implements the synthetic investigation bootstrap pipeline — HYDRA's solution to the cold start problem. By processing public threat intelligence through the same investigation pipeline that production alerts use, HYDRA pre-populates its entity graph with 50K+ known-threat entities before any customer goes live.

## Context

HYDRA's moat is a data flywheel: investigations → entity graph → detection intelligence → more customers → more investigations. But with zero customers, the corpus is empty. The bootstrap pipeline solves this by running synthetic investigations against public threat data.

Sprint 1G added the entity graph schema (investigations, entities, entity_edges, entity_observations tables) and three Temporal activities (extract_entities, write_entity_graph, embed_investigation). Sprint 1H uses these activities to process public threat intelligence.

## Deliverables

### 1H-1: MITRE ATT&CK Ingestion

Create `worker/bootstrap/mitre_attack.py`:

1. Download the MITRE ATT&CK Enterprise matrix from the STIX/TAXII endpoint or the static JSON:
   - URL: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
   - For air-gap: bundle the JSON file in the Docker image at build time, fall back to bundled if download fails

2. Parse each technique:
   - Extract: technique_id (e.g., T1110.003), name, description, platforms, tactics, data_sources
   - Extract procedure examples (the "uses" relationships) — these describe real attack behaviors
   - Extract associated software and groups

3. For each technique, generate a synthetic investigation:
   - Use the technique description + procedure examples as the "alert context"
   - Run through extract_entities activity to extract IOCs, techniques, relationships
   - Run through embed_investigation to create investigation record with `source = 'bootstrap'`
   - Run through write_entity_graph to populate entities and edges

4. Store technique metadata:
```sql
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id VARCHAR(20) PRIMARY KEY,  -- T1110.003
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tactics TEXT[],                         -- initial-access, execution, persistence, etc.
    platforms TEXT[],                       -- Windows, Linux, macOS, etc.
    data_sources TEXT[],
    detection_hints TEXT,                   -- MITRE's detection guidance
    last_synced TIMESTAMPTZ DEFAULT NOW()
);
```

### 1H-2: CISA Advisory Ingestion

Create `worker/bootstrap/cisa_advisories.py`:

1. Fetch CISA Known Exploited Vulnerabilities (KEV) catalog:
   - URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   - Parse each vulnerability: CVE ID, vendor, product, description, required_action, due_date

2. Fetch recent CISA Cybersecurity Advisories via RSS/JSON:
   - URL: `https://www.cisa.gov/news-events/cybersecurity-advisories` (or available JSON feed)
   - Parse: advisory title, summary, IOCs if available, recommended actions

3. For each advisory with sufficient detail:
   - Generate synthetic alert context from the advisory description
   - Run through the entity extraction → graph write pipeline
   - Tag investigations with `source = 'bootstrap'` and link to CVE IDs

### 1H-3: AlienVault OTX Ingestion (Optional — API Key Required)

Create `worker/bootstrap/otx_pulses.py`:

1. If OTX_API_KEY environment variable is set, fetch recent pulses:
   - URL: `https://otx.alienvault.com/api/v1/pulses/subscribed`
   - Parse each pulse: name, description, indicators (IPs, domains, hashes, URLs), tags, ATT&CK techniques

2. For each pulse:
   - Extract all indicators as entities
   - Build edges between indicators that appear together
   - Create investigation record with `source = 'bootstrap'`
   - Map pulse tags to MITRE ATT&CK technique IDs where possible

3. If no API key: skip gracefully with log message.

### 1H-4: Bootstrap Orchestrator

Create `worker/bootstrap/orchestrator.py`:

1. Temporal workflow: `BootstrapPipelineWorkflow`
   - Activity 1: `sync_mitre_attack` — download + parse + ingest all techniques
   - Activity 2: `sync_cisa_kev` — download + parse + ingest KEV catalog
   - Activity 3: `sync_cisa_advisories` — download + parse + ingest recent advisories
   - Activity 4: `sync_otx_pulses` — download + parse + ingest OTX (if API key available)
   - Activity 5: `compute_bootstrap_stats` — count entities, edges, investigations created

2. Temporal cron schedule: run daily at 02:00 UTC
   - MITRE ATT&CK: full re-sync weekly (techniques rarely change)
   - CISA KEV: daily (new CVEs added regularly)
   - OTX: daily (new pulses frequent)
   - Use `last_synced` timestamps to avoid re-processing unchanged data

3. Bootstrap CLI command:
   - `python -m bootstrap.orchestrator --run-now` — trigger immediate full sync
   - `python -m bootstrap.orchestrator --stats` — print entity/investigation counts
   - `python -m bootstrap.orchestrator --source mitre` — sync specific source only

### 1H-5: Bootstrap Dashboard Metrics

Add to existing Prometheus metrics (or create if Sprint 1F not yet done):
- `hydra_bootstrap_investigations_total{source}` — counter (source: mitre, cisa_kev, cisa_advisory, otx)
- `hydra_bootstrap_entities_total{source, entity_type}` — counter
- `hydra_bootstrap_last_sync_timestamp{source}` — gauge
- `hydra_bootstrap_sync_duration_seconds{source}` — histogram

### 1H-6: Air-Gap Bootstrap Bundle

For air-gapped deployments, the bootstrap data must be bundled:

1. Create `scripts/export_bootstrap_bundle.sh`:
   - Downloads MITRE ATT&CK JSON, CISA KEV JSON to `bootstrap/data/`
   - Packages as a tar.gz for offline import

2. Modify bootstrap orchestrator to check for local files first:
   - If `bootstrap/data/enterprise-attack.json` exists, use it instead of downloading
   - If `bootstrap/data/known_exploited_vulnerabilities.json` exists, use it
   - Log whether using online or offline source

## File Structure

```
worker/bootstrap/
    __init__.py
    orchestrator.py          # Temporal workflow + CLI
    mitre_attack.py          # MITRE ATT&CK parser + ingester
    cisa_advisories.py       # CISA KEV + advisory parser
    otx_pulses.py            # AlienVault OTX parser (optional)
    data/                    # Bundled offline data (for air-gap)
        .gitkeep
migrations/
    003_sprint1h_bootstrap.sql  # mitre_techniques table + bootstrap indexes
```

## Important Constraints

- All bootstrap investigations must have `source = 'bootstrap'` — never 'production'
- Bootstrap entities have `tenant_id = NULL` (shared across all tenants)
- Bootstrap data is weighted lower than production data in all intelligence scoring
- Air-gap mode must work without internet access
- The bootstrap pipeline uses the SAME extract_entities, write_entity_graph, embed_investigation activities as production — no separate code path
- Network access required for downloads — the worker container currently has `--network=none` for the sandbox only, the worker process itself has network access to internal services. Verify the worker can reach external URLs or add a separate bootstrap container with network access.

## Definition of Done

- [ ] `python -m bootstrap.orchestrator --run-now` successfully ingests MITRE ATT&CK techniques
- [ ] CISA KEV catalog ingested with entities extracted
- [ ] `SELECT COUNT(*) FROM investigations WHERE source = 'bootstrap';` returns > 0
- [ ] `SELECT COUNT(*) FROM entities WHERE tenant_id IS NULL;` returns > 0 (shared bootstrap entities)
- [ ] `SELECT COUNT(DISTINCT entity_type) FROM entities WHERE tenant_id IS NULL;` shows multiple entity types
- [ ] Air-gap bundle: `scripts/export_bootstrap_bundle.sh` creates offline package
- [ ] Running bootstrap twice doesn't create duplicates (idempotent via last_synced + entity_hash dedup)
- [ ] Git commit: "Sprint 1H: Bootstrap pipeline — MITRE/CISA/OTX ingestion for cold start"
