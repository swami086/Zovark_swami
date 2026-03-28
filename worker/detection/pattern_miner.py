"""Pattern miner — discovers attack patterns from investigation corpus.

Queries entity_observations + investigations to find technique-entity correlations
and creates detection_candidates for Sigma rule generation.
"""

import os
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


@activity.defn
async def mine_attack_patterns(data: dict) -> dict:
    """Mine attack patterns from investigation corpus.

    Finds technique-entity-role correlations across investigations
    and creates detection_candidates entries.

    Input: {min_investigations: 2}
    Returns: {candidates_found, candidates_created, candidates_updated}
    """
    min_investigations = data.get("min_investigations", 2)
    candidates_found = 0
    candidates_created = 0
    candidates_updated = 0

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Find technique-entity-role patterns
            cur.execute("""
                SELECT
                    eo.mitre_technique as technique,
                    eo.role,
                    e.entity_type,
                    COUNT(DISTINCT eo.investigation_id) as investigation_count,
                    AVG(i.risk_score) as avg_risk_score,
                    COUNT(DISTINCT i.tenant_id) as tenant_spread
                FROM entity_observations eo
                JOIN entities e ON e.id = eo.entity_id
                JOIN investigations i ON i.id = eo.investigation_id
                WHERE eo.mitre_technique IS NOT NULL
                  AND i.verdict IN ('true_positive', 'suspicious')
                  AND NOT COALESCE(i.injection_detected, false)
                GROUP BY eo.mitre_technique, eo.role, e.entity_type
                HAVING COUNT(DISTINCT eo.investigation_id) >= %s
                ORDER BY investigation_count DESC
            """, (min_investigations,))
            patterns = cur.fetchall()

            # Group by technique
            technique_patterns = {}
            for p in patterns:
                tech = p["technique"]
                if tech not in technique_patterns:
                    technique_patterns[tech] = {
                        "entity_types": [],
                        "roles": [],
                        "investigation_count": 0,
                        "avg_risk_score": 0,
                        "tenant_spread": 0,
                    }
                tp = technique_patterns[tech]
                if p["entity_type"] not in tp["entity_types"]:
                    tp["entity_types"].append(p["entity_type"])
                if p["role"] not in tp["roles"]:
                    tp["roles"].append(p["role"])
                tp["investigation_count"] = max(tp["investigation_count"], p["investigation_count"])
                tp["avg_risk_score"] = max(tp["avg_risk_score"], float(p["avg_risk_score"] or 0))
                tp["tenant_spread"] = max(tp["tenant_spread"], p["tenant_spread"])

            candidates_found = len(technique_patterns)

            # Also find edge patterns per technique
            cur.execute("""
                SELECT
                    eo.mitre_technique as technique,
                    ee.edge_type,
                    COUNT(DISTINCT eo.investigation_id) as edge_count
                FROM entity_observations eo
                JOIN entity_edges ee ON (
                    ee.source_entity_id = eo.entity_id
                    OR ee.target_entity_id = eo.entity_id
                )
                WHERE eo.mitre_technique IS NOT NULL
                GROUP BY eo.mitre_technique, ee.edge_type
                HAVING COUNT(DISTINCT eo.investigation_id) >= %s
                ORDER BY edge_count DESC
            """, (min_investigations,))
            edge_patterns = cur.fetchall()

            technique_edges = {}
            for ep in edge_patterns:
                tech = ep["technique"]
                if tech not in technique_edges:
                    technique_edges[tech] = []
                technique_edges[tech].append(ep["edge_type"])

            # Upsert detection candidates
            for tech, tp in technique_patterns.items():
                entity_types = sorted(tp["entity_types"])
                roles = sorted(tp["roles"])
                edges = sorted(technique_edges.get(tech, []))

                # Compute pattern signature
                sig_input = f"{tech}:{','.join(entity_types)}:{','.join(roles)}"
                pattern_signature = hashlib.sha256(sig_input.encode()).hexdigest()

                pattern_desc = (
                    f"Technique {tech} observed with entity types [{', '.join(entity_types)}] "
                    f"in roles [{', '.join(roles)}] across {tp['investigation_count']} investigations"
                )

                cur.execute("""
                    INSERT INTO detection_candidates
                    (technique_id, pattern_signature, pattern_description, entity_types,
                     edge_patterns, investigation_count, tenant_spread, avg_risk_score)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (pattern_signature) DO UPDATE SET
                        investigation_count = EXCLUDED.investigation_count,
                        tenant_spread = EXCLUDED.tenant_spread,
                        avg_risk_score = EXCLUDED.avg_risk_score,
                        pattern_description = EXCLUDED.pattern_description
                    RETURNING (xmax = 0) as is_insert
                """, (
                    tech, pattern_signature, pattern_desc, entity_types,
                    edges, tp["investigation_count"], tp["tenant_spread"],
                    round(tp["avg_risk_score"], 1)
                ))
                row = cur.fetchone()
                if row and row["is_insert"]:
                    candidates_created += 1
                else:
                    candidates_updated += 1

        conn.commit()
    except Exception as e:
        print(f"Pattern mining error: {e}")
        conn.rollback()
    finally:
        conn.close()

    print(f"Pattern mining: {candidates_found} patterns found, {candidates_created} created, {candidates_updated} updated")
    return {
        "candidates_found": candidates_found,
        "candidates_created": candidates_created,
        "candidates_updated": candidates_updated,
    }
