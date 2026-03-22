"""Cross-tenant entity resolution — materialized view refresh, entity intelligence, threat scoring.

Sprint 1K: privacy-preserving cross-tenant aggregation with SHA256 hashes.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


@activity.defn
async def refresh_cross_tenant_intel(data: dict) -> dict:
    """Refresh the cross_tenant_intel materialized view and update entity tenant_counts.

    Returns: {entities_correlated, multi_tenant_entities}
    """
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # CONCURRENTLY requires a unique index (idx_cross_tenant_hash exists)
            cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY cross_tenant_intel")

            # Update entities.tenant_count from the materialized view
            cur.execute("""
                UPDATE entities e
                SET tenant_count = cti.tenant_count
                FROM cross_tenant_intel cti
                WHERE e.entity_hash = cti.entity_hash
            """)
            entities_correlated = cur.rowcount

            # Count multi-tenant entities
            cur.execute("SELECT count(*) FROM cross_tenant_intel")
            multi_tenant_entities = cur.fetchone()[0]

        conn.commit()

        print(f"Cross-tenant refresh: {entities_correlated} entities updated, {multi_tenant_entities} multi-tenant entities")

        return {
            "entities_correlated": entities_correlated,
            "multi_tenant_entities": multi_tenant_entities,
        }

    except Exception as e:
        print(f"refresh_cross_tenant_intel error: {e}")
        conn.rollback()
        return {"entities_correlated": 0, "multi_tenant_entities": 0, "error": str(e)}
    finally:
        conn.close()


@activity.defn
async def get_entity_intelligence(data: dict) -> dict:
    """Get cross-tenant intelligence for an entity. Privacy-safe: never exposes other tenant data.

    Input: {entity_hash, tenant_id}
    Returns: {entity_hash, entity_type, global_threat_score, tenant_count, investigation_count,
              your_investigations, first_seen_globally, last_seen_globally, mitre_techniques}
    """
    entity_hash = data.get("entity_hash")
    tenant_id = data.get("tenant_id")

    if not entity_hash or not tenant_id:
        return {"entity_hash": entity_hash, "error": "Missing parameters"}

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Query cross_tenant_public (privacy-safe, no tenant_ids exposed)
            cur.execute("""
                SELECT entity_hash, entity_type, tenant_count, investigation_count,
                       max_observations, max_threat_score, last_seen_globally
                FROM cross_tenant_public
                WHERE entity_hash = %s
            """, (entity_hash,))
            cross_tenant = cur.fetchone()

            if not cross_tenant:
                # Not a multi-tenant entity — return basic info from entities table
                cur.execute("""
                    SELECT entity_hash, entity_type, threat_score, observation_count,
                           first_seen, last_seen
                    FROM entities
                    WHERE entity_hash = %s AND tenant_id = %s
                    LIMIT 1
                """, (entity_hash, tenant_id))
                local = cur.fetchone()
                if not local:
                    return {"entity_hash": entity_hash, "error": "Entity not found"}
                return {
                    "entity_hash": entity_hash,
                    "entity_type": local["entity_type"],
                    "global_threat_score": local.get("threat_score", 0),
                    "tenant_count": 1,
                    "investigation_count": 0,
                    "your_investigations": [],
                    "first_seen_globally": str(local.get("first_seen", "")),
                    "last_seen_globally": str(local.get("last_seen", "")),
                    "mitre_techniques": [],
                }

            # Get investigations for this entity within the requesting tenant only
            cur.execute("""
                SELECT DISTINCT i.id::text as investigation_id, i.verdict, i.risk_score,
                       i.confidence, i.created_at::text
                FROM investigations i
                JOIN entity_observations eo ON eo.investigation_id = i.id
                JOIN entities e ON e.id = eo.entity_id
                WHERE e.entity_hash = %s
                AND i.tenant_id = %s
                AND NOT COALESCE(i.injection_detected, false)
                ORDER BY i.created_at::text DESC
                LIMIT 20
            """, (entity_hash, tenant_id))
            your_investigations = [dict(r) for r in cur.fetchall()]

            # Get MITRE techniques from entity_edges for this entity within requesting tenant
            cur.execute("""
                SELECT DISTINCT ee.mitre_technique
                FROM entity_edges ee
                JOIN entities e ON (e.id = ee.source_entity_id OR e.id = ee.target_entity_id)
                WHERE e.entity_hash = %s
                AND ee.tenant_id = %s
                AND ee.mitre_technique IS NOT NULL
            """, (entity_hash, tenant_id))
            mitre_techniques = [r["mitre_technique"] for r in cur.fetchall()]

            # Get first_seen across all tenants (aggregate, not tenant-specific)
            cur.execute("""
                SELECT MIN(first_seen)::text as first_seen_globally
                FROM entities
                WHERE entity_hash = %s
            """, (entity_hash,))
            first_seen_row = cur.fetchone()

        return {
            "entity_hash": entity_hash,
            "entity_type": cross_tenant["entity_type"],
            "global_threat_score": cross_tenant.get("max_threat_score", 0),
            "tenant_count": cross_tenant["tenant_count"],
            "investigation_count": cross_tenant["investigation_count"],
            "your_investigations": your_investigations,
            "first_seen_globally": str(first_seen_row["first_seen_globally"]) if first_seen_row else "",
            "last_seen_globally": str(cross_tenant.get("last_seen_globally", "")),
            "mitre_techniques": mitre_techniques,
        }

    except Exception as e:
        print(f"get_entity_intelligence error: {e}")
        return {"entity_hash": entity_hash, "error": str(e)}
    finally:
        conn.close()


@activity.defn
async def compute_threat_score(data: dict) -> dict:
    """Compute threat score for an entity based on observations, cross-tenant presence, verdicts, recency.

    Input: {entity_id, tenant_id}
    Returns: {entity_id, threat_score, factors}
    """
    entity_id = data.get("entity_id")
    data.get("tenant_id")

    if not entity_id:
        return {"entity_id": entity_id, "threat_score": 0, "factors": {}, "error": "Missing entity_id"}

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get entity basics
            cur.execute("""
                SELECT entity_hash, observation_count, last_seen
                FROM entities
                WHERE id = %s::uuid
            """, (entity_id,))
            entity = cur.fetchone()

            if not entity:
                return {"entity_id": entity_id, "threat_score": 0, "factors": {}, "error": "Entity not found"}

            observation_count = entity.get("observation_count", 1)
            last_seen = entity.get("last_seen")

            # Get cross-tenant count
            cur.execute("""
                SELECT tenant_count FROM cross_tenant_intel WHERE entity_hash = %s
            """, (entity["entity_hash"],))
            ct_row = cur.fetchone()
            tenant_count = ct_row["tenant_count"] if ct_row else 1

            # Get verdict distribution from related investigations
            cur.execute("""
                SELECT i.verdict, count(*) as cnt
                FROM investigations i
                JOIN entity_observations eo ON eo.investigation_id = i.id
                WHERE eo.entity_id = %s::uuid
                AND NOT COALESCE(i.injection_detected, false)
                GROUP BY i.verdict
            """, (entity_id,))
            verdict_rows = cur.fetchall()
            tp_count = sum(r["cnt"] for r in verdict_rows if r["verdict"] == "true_positive")
            total_count = sum(r["cnt"] for r in verdict_rows)

            # Compute score components
            base = min(observation_count * 5, 30)
            multi_tenant_bonus = min(tenant_count * 15, 45)
            verdict_score = round((tp_count / total_count) * 25, 1) if total_count > 0 else 0

            # Recency
            recency = 0
            if last_seen:
                now = datetime.now(timezone.utc)
                age_hours = (now - last_seen).total_seconds() / 3600
                if age_hours <= 24:
                    recency = 10
                elif age_hours <= 168:  # 7 days
                    recency = 5

            threat_score = min(int(base + multi_tenant_bonus + verdict_score + recency), 100)

            # Update entity
            cur.execute("""
                UPDATE entities SET threat_score = %s WHERE id = %s::uuid
            """, (threat_score, entity_id))

        conn.commit()

        factors = {
            "base_observation": base,
            "multi_tenant_bonus": multi_tenant_bonus,
            "verdict_score": verdict_score,
            "recency": recency,
            "observation_count": observation_count,
            "tenant_count": tenant_count,
            "tp_count": tp_count,
            "total_investigations": total_count,
        }

        return {
            "entity_id": entity_id,
            "threat_score": threat_score,
            "factors": factors,
        }

    except Exception as e:
        print(f"compute_threat_score error: {e}")
        conn.rollback()
        return {"entity_id": entity_id, "threat_score": 0, "factors": {}, "error": str(e)}
    finally:
        conn.close()


@activity.defn
async def correlate_entities(data: dict) -> dict:
    """Find entities seen by 2+ tenants and compute threat scores.

    Privacy-preserving: uses SHA256 hashes, never exposes raw entity values
    cross-tenant. Populates cross_tenant_entities table with aggregated data.

    Input: {}
    Returns: {entities_found, entities_upserted, high_threat_count, alerts_generated}
    """
    entities_found = 0
    entities_upserted = 0
    high_threat_count = 0
    alerts_generated = 0

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Find entities observed by 2+ tenants
            cur.execute("""
                SELECT e.entity_hash, e.entity_type, e.value,
                       COUNT(DISTINCT e.tenant_id) as tenant_count,
                       COUNT(*) as total_observations,
                       MAX(e.last_seen) as latest_observation,
                       MIN(e.first_seen) as earliest_observation,
                       MAX(e.observation_count) as max_obs_count
                FROM entities e
                WHERE e.tenant_id IS NOT NULL
                GROUP BY e.entity_hash, e.entity_type, e.value
                HAVING COUNT(DISTINCT e.tenant_id) >= 2
                ORDER BY COUNT(DISTINCT e.tenant_id) DESC
            """)
            cross_entities = cur.fetchall()
            entities_found = len(cross_entities)

            for ent in cross_entities:
                entity_hash = ent["entity_hash"]
                tenant_count = ent["tenant_count"]
                observation_count = ent["total_observations"]
                latest_observation = ent["latest_observation"]
                earliest_observation = ent["earliest_observation"]

                # Check for attacker role context bonus
                cur.execute("""
                    SELECT COUNT(*) as attacker_count
                    FROM entity_observations eo
                    JOIN entities e ON e.id = eo.entity_id
                    WHERE e.entity_hash = %s AND eo.role = 'attacker'
                """, (entity_hash,))
                attacker_row = cur.fetchone()
                has_attacker_role = (attacker_row["attacker_count"] or 0) > 0

                # Check for source in attack context
                cur.execute("""
                    SELECT COUNT(*) as source_count
                    FROM entity_observations eo
                    JOIN entities e ON e.id = eo.entity_id
                    JOIN investigations i ON i.id = eo.investigation_id
                    WHERE e.entity_hash = %s AND eo.role = 'source'
                      AND i.verdict IN ('true_positive', 'suspicious')
                """, (entity_hash,))
                source_row = cur.fetchone()
                has_attack_source = (source_row["source_count"] or 0) > 0

                # Check for linked ATT&CK technique
                cur.execute("""
                    SELECT COUNT(DISTINCT eo.mitre_technique) as tech_count
                    FROM entity_observations eo
                    JOIN entities e ON e.id = eo.entity_id
                    WHERE e.entity_hash = %s AND eo.mitre_technique IS NOT NULL
                """, (entity_hash,))
                tech_row = cur.fetchone()
                has_technique = (tech_row["tech_count"] or 0) > 0

                # Compute threat score
                context_bonus = 0
                if has_attacker_role:
                    context_bonus += 20
                if has_attack_source:
                    context_bonus += 10
                if has_technique:
                    context_bonus += 15

                base_score = (tenant_count * 15) + (observation_count * 5) + context_bonus

                # Temporal decay: reduce by 5 points per month since last observation
                if latest_observation:
                    now = datetime.now(timezone.utc)
                    age_months = (now - latest_observation).days / 30.0
                    decay = int(age_months * 5)
                    base_score -= decay

                threat_score = min(max(base_score, 0), 100)

                # Build metadata
                metadata = {
                    "context_bonus": context_bonus,
                    "has_attacker_role": has_attacker_role,
                    "has_attack_source": has_attack_source,
                    "has_technique": has_technique,
                    "observation_count": observation_count,
                }

                # Upsert into cross_tenant_entities
                cur.execute("""
                    INSERT INTO cross_tenant_entities
                    (entity_type, entity_value, entity_hash, tenant_count,
                     first_seen, last_seen, threat_score, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (entity_hash) DO UPDATE SET
                        tenant_count = EXCLUDED.tenant_count,
                        last_seen = GREATEST(cross_tenant_entities.last_seen, EXCLUDED.last_seen),
                        threat_score = EXCLUDED.threat_score,
                        metadata = EXCLUDED.metadata
                """, (
                    ent["entity_type"], ent["value"], entity_hash,
                    tenant_count, earliest_observation, latest_observation,
                    threat_score, json.dumps(metadata)
                ))
                entities_upserted += 1

                # Update entities table threat_score
                cur.execute("""
                    UPDATE entities SET
                        threat_score = %s,
                        tenant_count = %s,
                        last_seen = GREATEST(last_seen, %s)
                    WHERE entity_hash = %s
                """, (threat_score, tenant_count, latest_observation, entity_hash))

                # Generate intelligence alert when crossing threshold
                if threat_score >= 70:
                    high_threat_count += 1

                    # Get associated techniques for the alert
                    cur.execute("""
                        SELECT DISTINCT eo.mitre_technique
                        FROM entity_observations eo
                        JOIN entities e ON e.id = eo.entity_id
                        WHERE e.entity_hash = %s AND eo.mitre_technique IS NOT NULL
                        LIMIT 10
                    """, (entity_hash,))
                    techniques = [r["mitre_technique"] for r in cur.fetchall()]

                    # Insert audit event for cross-tenant intelligence
                    try:
                        cur.execute("""
                            INSERT INTO audit_events
                            (tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
                            SELECT DISTINCT e.tenant_id,
                                'cross_tenant_intelligence', 'system', 'entity',
                                %s,
                                %s
                            FROM entities e
                            WHERE e.entity_hash = %s AND e.tenant_id IS NOT NULL
                            LIMIT 1
                        """, (
                            entity_hash,
                            json.dumps({
                                "entity_type": ent["entity_type"],
                                "entity_value": ent["value"],
                                "threat_score": float(threat_score),
                                "tenant_count": tenant_count,
                                "techniques": techniques,
                            }),
                            entity_hash,
                        ))
                        alerts_generated += 1
                    except Exception:
                        pass  # audit log failure is non-fatal

        conn.commit()

        print(
            f"correlate_entities: found={entities_found}, upserted={entities_upserted}, "
            f"high_threat={high_threat_count}, alerts={alerts_generated}"
        )

        return {
            "entities_found": entities_found,
            "entities_upserted": entities_upserted,
            "high_threat_count": high_threat_count,
            "alerts_generated": alerts_generated,
        }

    except Exception as e:
        print(f"correlate_entities error: {e}")
        conn.rollback()
        return {
            "entities_found": 0,
            "entities_upserted": 0,
            "high_threat_count": 0,
            "alerts_generated": 0,
            "error": str(e),
        }
    finally:
        conn.close()
