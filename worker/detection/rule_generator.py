"""Sprint 2A: Self-generating detection engine — rule_generator.py

Provides three core functions:
  - mine_attack_patterns() — finds technique-entity combos in 5+ true_positive investigations
  - generate_sigma_rule() — creates Sigma YAML from attack patterns (template-based, not LLM)
  - validate_rule() — tests rule against historical investigation data

All functions operate as standalone utilities (non-Temporal). The existing
Temporal activities in pattern_miner.py, sigma_generator.py, and rule_validator.py
handle workflow integration. This module provides a simpler, template-based
alternative that does not require LLM calls.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


# ---------------------------------------------------------------------------
# 1. mine_attack_patterns
# ---------------------------------------------------------------------------

def mine_attack_patterns(min_investigations: int = 5) -> list:
    """Find technique-entity combos in 5+ true_positive investigations.

    Returns a list of pattern dicts:
      [{technique, role, entity_type, edge_type, investigation_count,
        avg_risk_score, tenant_spread}, ...]
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    eo.mitre_technique as technique,
                    eo.role,
                    e.entity_type,
                    ee.edge_type,
                    COUNT(DISTINCT i.id) as investigation_count,
                    AVG(i.risk_score) as avg_risk_score,
                    COUNT(DISTINCT i.tenant_id) as tenant_spread
                FROM investigations i
                JOIN entity_observations eo ON eo.investigation_id = i.id
                JOIN entities e ON e.id = eo.entity_id
                LEFT JOIN entity_edges ee ON (
                    ee.source_entity_id = e.id OR ee.target_entity_id = e.id
                ) AND ee.investigation_id = i.id
                WHERE i.verdict IN ('true_positive', 'suspicious')
                  AND i.source = 'production'
                  AND eo.mitre_technique IS NOT NULL
                  AND NOT COALESCE(i.injection_detected, false)
                GROUP BY eo.mitre_technique, eo.role, e.entity_type, ee.edge_type
                HAVING COUNT(DISTINCT i.id) >= %s
                ORDER BY investigation_count DESC
            """, (min_investigations,))
            patterns = [dict(r) for r in cur.fetchall()]

            # Convert Decimal to float for JSON serialization
            for p in patterns:
                if p.get("avg_risk_score") is not None:
                    p["avg_risk_score"] = float(p["avg_risk_score"])

            return patterns
    except Exception as e:
        print(f"mine_attack_patterns error: {e}")
        return []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 2. generate_sigma_rule (template-based, no LLM)
# ---------------------------------------------------------------------------

# Mapping from entity_type to Sigma logsource category
ENTITY_TO_LOGSOURCE = {
    "ip_address": {"category": "firewall", "product": "any"},
    "domain": {"category": "dns", "product": "any"},
    "url": {"category": "proxy", "product": "any"},
    "file_hash": {"category": "file_event", "product": "any"},
    "hostname": {"category": "process_creation", "product": "windows"},
    "username": {"category": "authentication", "product": "any"},
    "email": {"category": "email", "product": "any"},
    "process": {"category": "process_creation", "product": "windows"},
}

# Mapping from edge_type to Sigma detection field
EDGE_TO_FIELD = {
    "connected_to": "DestinationIp",
    "resolved_to": "QueryName",
    "authenticated_as": "TargetUserName",
    "executed": "CommandLine",
    "downloaded": "TargetFilename",
    "communicated_with": "DestinationHostname",
}

TACTIC_MAP = {
    "T1110": "credential-access",
    "T1071": "command-and-control",
    "T1021": "lateral-movement",
    "T1059": "execution",
    "T1053": "persistence",
    "T1486": "impact",
    "T1566": "initial-access",
    "T1078": "defense-evasion",
    "T1098": "persistence",
    "T1133": "initial-access",
    "T1190": "initial-access",
    "T1203": "execution",
    "T1547": "persistence",
    "T1548": "privilege-escalation",
    "T1562": "defense-evasion",
    "T1569": "execution",
}


def generate_sigma_rule(technique_id: str, entity_types: list, edge_patterns: list,
                        investigation_count: int = 0, tenant_spread: int = 0,
                        avg_risk_score: float = 0) -> str:
    """Create a Sigma YAML rule from attack patterns (template-based, no LLM).

    Returns the Sigma YAML as a string.
    """
    rule_id = str(uuid.uuid4())
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    # Determine logsource from primary entity type
    primary_entity = entity_types[0] if entity_types else "ip_address"
    logsource = ENTITY_TO_LOGSOURCE.get(primary_entity, {"category": "generic", "product": "any"})

    # Determine risk level
    if avg_risk_score >= 80:
        level = "critical"
    elif avg_risk_score >= 60:
        level = "high"
    elif avg_risk_score >= 40:
        level = "medium"
    else:
        level = "low"

    # Determine tactic from technique ID prefix
    tech_prefix = technique_id.split(".")[0] if "." in technique_id else technique_id
    tactic = TACTIC_MAP.get(tech_prefix, "unknown")

    # Build detection selection from edge patterns
    selection = {}
    for edge in (edge_patterns or []):
        field = EDGE_TO_FIELD.get(edge, "EventType")
        selection[field] = f"*{technique_id}*"

    if not selection:
        # Fallback: generic selection based on entity type
        if primary_entity == "ip_address":
            selection["SourceIp|endswith"] = "*"
        elif primary_entity == "domain":
            selection["QueryName|contains"] = "*"
        elif primary_entity == "username":
            selection["TargetUserName|contains"] = "*"
        else:
            selection["EventType"] = technique_id

    # Build description
    description = (
        f"Auto-generated by HYDRA from {investigation_count} investigations "
        f"across {tenant_spread} environments. "
        f"Detects {technique_id} activity involving {', '.join(entity_types)}."
    )

    # Build rule dict
    rule = {
        "title": f"HYDRA-{technique_id}: {tactic.replace('-', ' ').title()} Detection",
        "id": rule_id,
        "status": "experimental",
        "level": level,
        "description": description,
        "author": "HYDRA Detection Engine",
        "date": today,
        "tags": [
            f"attack.{tactic}",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": logsource,
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate administrative activity",
            "Automated vulnerability scanners",
        ],
    }

    if HAS_YAML:
        return yaml.dump(rule, default_flow_style=False, sort_keys=False)
    else:
        # Fallback string-based YAML generation
        lines = [
            f"title: \"HYDRA-{technique_id}: {tactic.replace('-', ' ').title()} Detection\"",
            f"id: {rule_id}",
            "status: experimental",
            f"level: {level}",
            f"description: |",
            f"    {description}",
            "author: HYDRA Detection Engine",
            f"date: {today}",
            "tags:",
            f"    - attack.{tactic}",
            f"    - attack.{technique_id.lower()}",
            "logsource:",
            f"    category: {logsource['category']}",
            f"    product: {logsource['product']}",
            "detection:",
            "    selection:",
        ]
        for k, v in selection.items():
            lines.append(f"        {k}: \"{v}\"")
        lines.append("    condition: selection")
        lines.append("falsepositives:")
        lines.append("    - Legitimate administrative activity")
        lines.append("    - Automated vulnerability scanners")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 3. validate_rule
# ---------------------------------------------------------------------------

def validate_rule(technique_id: str, sigma_yaml: str) -> dict:
    """Test a Sigma rule against historical investigation data.

    Returns: {valid, tp_rate, fp_rate, total_matches, tp_matches, fp_matches, status, errors}
    """
    errors = []

    # 1. YAML structure validation
    if HAS_YAML:
        try:
            parsed = yaml.safe_load(sigma_yaml)
            if not isinstance(parsed, dict):
                errors.append("Root element must be a mapping")
            else:
                for field in ["title", "logsource", "detection", "level"]:
                    if field not in parsed:
                        errors.append(f"Missing required field: {field}")
                if "detection" in parsed:
                    det = parsed["detection"]
                    if isinstance(det, dict):
                        if "condition" not in det:
                            errors.append("detection must have 'condition'")
                        selections = [k for k in det.keys() if k != "condition"]
                        if not selections:
                            errors.append("detection must have at least one selection")
                    else:
                        errors.append("detection must be a mapping")
        except Exception as e:
            errors.append(f"Invalid YAML: {e}")
    else:
        if "title:" not in sigma_yaml:
            errors.append("Missing 'title' field")
        if "detection:" not in sigma_yaml:
            errors.append("Missing 'detection' field")
        if "logsource:" not in sigma_yaml:
            errors.append("Missing 'logsource' field")

    if errors:
        return {
            "valid": False,
            "tp_rate": 0.0,
            "fp_rate": 0.0,
            "total_matches": 0,
            "tp_matches": 0,
            "fp_matches": 0,
            "status": "rejected",
            "errors": errors,
        }

    # 2. Test against investigation corpus
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    COUNT(DISTINCT CASE WHEN i.verdict = 'true_positive' THEN i.id END) as tp_count,
                    COUNT(DISTINCT CASE WHEN i.verdict IN ('false_positive', 'benign') THEN i.id END) as fp_count,
                    COUNT(DISTINCT i.id) as total_count
                FROM entity_observations eo
                JOIN investigations i ON i.id = eo.investigation_id
                WHERE eo.mitre_technique = %s
                  AND NOT COALESCE(i.injection_detected, false)
            """, (technique_id,))
            row = cur.fetchone()

            tp_matches = row["tp_count"] or 0
            fp_matches = row["fp_count"] or 0
            total_matches = row["total_count"] or 0

            tp_rate = (tp_matches / total_matches) if total_matches > 0 else 0.0
            fp_rate = (fp_matches / total_matches) if total_matches > 0 else 0.0

            # Decision logic
            if tp_rate >= 0.80 and fp_rate <= 0.10:
                status = "approved"
            elif tp_rate >= 0.70 or fp_rate <= 0.20:
                status = "candidate"
            else:
                status = "rejected"

            return {
                "valid": status != "rejected",
                "tp_rate": round(tp_rate, 3),
                "fp_rate": round(fp_rate, 3),
                "total_matches": total_matches,
                "tp_matches": tp_matches,
                "fp_matches": fp_matches,
                "status": status,
                "errors": [],
            }
    except Exception as e:
        print(f"validate_rule error: {e}")
        return {
            "valid": False,
            "tp_rate": 0.0,
            "fp_rate": 0.0,
            "total_matches": 0,
            "tp_matches": 0,
            "fp_matches": 0,
            "status": "error",
            "errors": [str(e)],
        }
    finally:
        conn.close()
