# HYDRA Sprint 1K — Cross-Tenant Entity Resolution
## Claude Code Prompt

---

You are building Sprint 1K for HYDRA, an AI-powered SOC investigation automation platform. This sprint activates Layer 2 of the moat: cross-tenant entity resolution. When the same malicious IP, domain, or file hash appears in investigations across multiple tenants, HYDRA recognizes it and elevates its threat confidence — creating a network effect where every customer improves intelligence for every other customer.

## Context

Sprint 1G created the entity graph tables (entities, entity_edges, entity_observations) with `entity_hash` as the cross-tenant dedup key. Sprint 1H populated the graph with bootstrap data (MITRE/CISA). Now production investigations are adding tenant-specific entities.

The entity_hash is SHA256 of `"{entity_type}:{normalized_value}"` — this means the same IP observed by two different tenants produces the same hash, enabling correlation without exposing which tenant saw it.

## Deliverables

### 1K-1: Cross-Tenant Entity Correlation Job

Create `worker/intelligence/entity_correlation.py`:

A Temporal workflow that runs periodically (every hour) and:

1. **Find cross-tenant entities:**
```sql
SELECT entity_hash, entity_type, value, 
       COUNT(DISTINCT tenant_id) as tenant_count,
       COUNT(*) as total_observations,
       ARRAY_AGG(DISTINCT tenant_id) as tenants
FROM entities 
WHERE tenant_id IS NOT NULL  -- exclude bootstrap
GROUP BY entity_hash, entity_type, value
HAVING COUNT(DISTINCT tenant_id) >= 2
ORDER BY COUNT(DISTINCT tenant_id) DESC;
```

2. **Compute threat scores:**
   - Base score from observation count and tenant spread
   - Formula: `threat_score = min(100, (tenant_count * 15) + (observation_count * 5) + context_bonus)`
   - `context_bonus`: +20 if entity appears as 'attacker' role, +10 if 'source' in attack context, +15 if linked to known ATT&CK technique
   - Temporal decay: reduce score by 5 points per month since last observation

3. **Update entity threat scores:**
```sql
UPDATE entities SET 
    threat_score = computed_score,
    tenant_count = actual_tenant_count,
    last_seen = GREATEST(last_seen, latest_observation)
WHERE entity_hash = :hash;
```

4. **Generate threat intelligence alerts:**
   - When an entity crosses the threshold (threat_score >= 70), generate a "cross-tenant intelligence" event in audit_events
   - Include: entity value, entity type, tenant count, associated ATT&CK techniques
   - This is the raw material for Phase 2 detection generation

### 1K-2: Privacy-Preserving Aggregation Layer

Create `worker/intelligence/privacy.py`:

Cross-tenant correlation must never leak which tenant saw an entity. Implement:

1. **Anonymized aggregation view:**
```sql
CREATE MATERIALIZED VIEW cross_tenant_intelligence AS
SELECT 
    e.entity_hash,
    e.entity_type,
    e.value,
    COUNT(DISTINCT e.tenant_id) as tenant_spread,
    COUNT(DISTINCT eo.investigation_id) as investigation_count,
    ARRAY_AGG(DISTINCT eo.mitre_technique) FILTER (WHERE eo.mitre_technique IS NOT NULL) as techniques,
    ARRAY_AGG(DISTINCT eo.role) as observed_roles,
    MAX(e.threat_score) as max_threat_score,
    MAX(e.last_seen) as last_observed
FROM entities e
LEFT JOIN entity_observations eo ON eo.entity_id = e.id
WHERE e.tenant_id IS NOT NULL
GROUP BY e.entity_hash, e.entity_type, e.value
HAVING COUNT(DISTINCT e.tenant_id) >= 2;
```

2. **Tenant-safe query functions:**
```python
def get_entity_intelligence(entity_hash: str, requesting_tenant_id: str) -> dict:
    """Return cross-tenant intelligence about an entity.
    
    Shows: threat score, tenant count, techniques, roles
    Never shows: which other tenants observed it
    """

def get_related_entities(entity_hash: str, requesting_tenant_id: str) -> list:
    """Return entities connected to this one via edges.
    
    Only returns edges from:
    - The requesting tenant's own investigations
    - Bootstrap/shared investigations
    Never returns edges from other tenants.
    """
```

3. **Privacy boundary rules (enforced in code):**
   - `tenant_count` is shared (anonymized count, no identities)
   - `techniques` and `roles` are shared (aggregated, no tenant attribution)
   - `investigation_id` is NEVER shared across tenants
   - `entity_edges` are only visible within a tenant's own context + bootstrap

### 1K-3: Entity Enrichment Pipeline

Create `worker/intelligence/enrichment.py`:

When a new entity is observed, check if it's already known:

1. **On entity write (hook into write_entity_graph activity):**
   - After upserting entity, check `cross_tenant_intelligence` view
   - If entity has `tenant_spread >= 2`: attach threat intelligence to the current investigation
   - Add to investigation metadata: `{"cross_tenant_intel": {"threat_score": 85, "tenant_spread": 4, "techniques": ["T1071.001"]}}`

2. **Enrichment sources (local, no external API calls):**
   - Cross-tenant observation data (from materialized view)
   - Bootstrap data (MITRE/CISA entities)
   - Historical entity edges within the same tenant

### 1K-4: Threat Intelligence API Endpoint

Add to Go API:

`GET /api/v1/intelligence/entity/{entity_hash}`
- Auth required (JWT)
- Returns: threat score, entity type, value, tenant spread (count only), associated techniques, observed roles
- Respects privacy boundaries: never returns other tenant IDs or investigation IDs
- Rate limited: 100 requests/minute per tenant

`GET /api/v1/intelligence/top-threats`
- Auth required (JWT)  
- Returns: top 50 entities by threat score that the requesting tenant has observed
- Enriched with cross-tenant intelligence (tenant_spread, techniques)

`GET /api/v1/intelligence/stats`
- Auth required (JWT)
- Returns: total entities, cross-tenant entities, top entity types, technique distribution

### 1K-5: Dashboard Widget

Update the React dashboard to show:
- "Cross-Tenant Intelligence" panel showing entities observed by multiple tenants
- Threat score badges on entity mentions in investigation results
- Simple entity graph visualization (nodes = entities, edges = relationships) using D3.js or vis.js

### 1K-6: Metrics

- `hydra_cross_tenant_entities_total` — gauge (entities seen by 2+ tenants)
- `hydra_entity_threat_score_distribution` — histogram
- `hydra_intelligence_queries_total{endpoint}` — counter
- `hydra_correlation_job_duration_seconds` — histogram
- `hydra_entities_enriched_total` — counter (entities that received cross-tenant enrichment)

## Important Constraints

- **Privacy is non-negotiable.** No tenant can learn which other tenants exist or what they've observed. Only anonymized counts and aggregated patterns cross the tenant boundary.
- The correlation job must be efficient — with 100K+ entities, full table scans won't work. Use the `entity_hash` index and process incrementally (only entities updated since last run).
- The materialized view must be refreshed after the correlation job runs: `REFRESH MATERIALIZED VIEW CONCURRENTLY cross_tenant_intelligence;` (requires unique index)
- All cross-tenant intelligence must work in air-gap mode (no external API calls for enrichment)
- The Go API changes require updating the API router and handlers — follow existing patterns in the api/ directory

## Definition of Done

- [ ] Correlation job identifies entities seen by 2+ tenants
- [ ] Threat scores computed and updated for cross-tenant entities
- [ ] Privacy boundary enforced: no tenant IDs leak across tenant boundaries
- [ ] `/api/v1/intelligence/entity/{hash}` returns enriched data
- [ ] `/api/v1/intelligence/top-threats` returns tenant-relevant threats
- [ ] Dashboard shows cross-tenant intelligence panel
- [ ] Materialized view refreshes without blocking reads
- [ ] Git commit: "Sprint 1K: Cross-tenant entity resolution + threat intelligence"
