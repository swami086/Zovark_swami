"""Rule validator — validates Sigma rules against investigation corpus.

Checks YAML structure, required fields, and tests TP/FP rates
against historical investigations.
"""

import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


def _validate_sigma_structure(sigma_yaml: str) -> dict:
    """Validate Sigma YAML structure and required fields.

    Returns: {valid, errors, parsed}
    """
    errors = []

    if not HAS_YAML:
        # Basic string validation
        has_title = "title:" in sigma_yaml
        has_detection = "detection:" in sigma_yaml
        has_logsource = "logsource:" in sigma_yaml
        has_level = "level:" in sigma_yaml
        if not has_title:
            errors.append("Missing 'title' field")
        if not has_detection:
            errors.append("Missing 'detection' field")
        if not has_logsource:
            errors.append("Missing 'logsource' field")
        if not has_level:
            errors.append("Missing 'level' field")
        return {"valid": len(errors) == 0, "errors": errors, "parsed": None}

    try:
        parsed = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as e:
        return {"valid": False, "errors": [f"Invalid YAML: {e}"], "parsed": None}

    if not isinstance(parsed, dict):
        return {"valid": False, "errors": ["Root element must be a mapping"], "parsed": None}

    # Required fields
    for field in ["title", "logsource", "detection", "level"]:
        if field not in parsed:
            errors.append(f"Missing required field: {field}")

    # Logsource validation
    if "logsource" in parsed:
        ls = parsed["logsource"]
        if isinstance(ls, dict):
            if "category" not in ls and "product" not in ls:
                errors.append("logsource must have 'category' or 'product'")
        else:
            errors.append("logsource must be a mapping")

    # Detection validation
    if "detection" in parsed:
        det = parsed["detection"]
        if isinstance(det, dict):
            if "condition" not in det:
                errors.append("detection must have 'condition'")
            # Should have at least one selection
            selections = [k for k in det.keys() if k != "condition"]
            if not selections:
                errors.append("detection must have at least one selection")
        else:
            errors.append("detection must be a mapping")

    return {"valid": len(errors) == 0, "errors": errors, "parsed": parsed}


@activity.defn
async def validate_sigma_rule(data: dict) -> dict:
    """Validate a Sigma rule and test against investigation corpus.

    Input: {candidate_id, technique_id, sigma_yaml}
    Returns: {candidate_id, valid, tp_rate, fp_rate, status, errors, investigations_matched}
    """
    candidate_id = data.get("candidate_id")
    technique_id = data.get("technique_id", "")
    sigma_yaml = data.get("sigma_yaml", "")

    # 1. Structure validation
    structure = _validate_sigma_structure(sigma_yaml)
    if not structure["valid"]:
        _update_candidate(candidate_id, "rejected", {
            "structure_valid": False,
            "errors": structure["errors"],
        })
        return {
            "candidate_id": candidate_id,
            "valid": False,
            "tp_rate": 0,
            "fp_rate": 0,
            "status": "rejected",
            "errors": structure["errors"],
            "investigations_matched": 0,
        }

    # 2. Test against investigation corpus
    tp_matches = 0
    fp_matches = 0
    total_matches = 0
    investigations_matched = 0

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Count investigations with this technique and TP verdict
            cur.execute("""
                SELECT
                    COUNT(DISTINCT CASE WHEN i.verdict IN ('true_positive') THEN i.id END) as tp_count,
                    COUNT(DISTINCT CASE WHEN i.verdict IN ('false_positive', 'benign') THEN i.id END) as fp_count,
                    COUNT(DISTINCT i.id) as total_count,
                    COUNT(DISTINCT i.tenant_id) as tenant_spread
                FROM entity_observations eo
                JOIN investigations i ON i.id = eo.investigation_id
                WHERE eo.mitre_technique = %s
                  AND NOT COALESCE(i.injection_detected, false)
            """, (technique_id,))
            row = cur.fetchone()
            if row:
                tp_matches = row["tp_count"]
                fp_matches = row["fp_count"]
                total_matches = row["total_count"]
                investigations_matched = total_matches
    finally:
        conn.close()

    # 3. Calculate rates
    tp_rate = (tp_matches / total_matches) if total_matches > 0 else 0
    fp_rate = (fp_matches / total_matches) if total_matches > 0 else 0

    # 4. Auto-approve decision
    if tp_rate >= 0.80 and fp_rate <= 0.10:
        status = "approved"
    elif tp_rate >= 0.70 or fp_rate <= 0.20:
        status = "candidate"  # Flagged for review
    else:
        status = "rejected"

    validation_result = {
        "structure_valid": True,
        "tp_matches": tp_matches,
        "fp_matches": fp_matches,
        "total_matches": total_matches,
        "tp_rate": round(tp_rate, 3),
        "fp_rate": round(fp_rate, 3),
        "auto_decision": status,
    }

    _update_candidate(candidate_id, status, validation_result)

    # 5. If approved, create detection rule
    rule_id = None
    if status == "approved" and sigma_yaml:
        rule_id = _create_detection_rule(
            candidate_id, technique_id, sigma_yaml,
            tp_rate, fp_rate, investigations_matched
        )

    print(f"Validation for {technique_id}: tp={tp_rate:.2f} fp={fp_rate:.2f} status={status}")
    return {
        "candidate_id": candidate_id,
        "valid": status != "rejected",
        "tp_rate": round(tp_rate, 3),
        "fp_rate": round(fp_rate, 3),
        "status": status,
        "errors": [],
        "investigations_matched": investigations_matched,
        "rule_id": rule_id,
    }


def _update_candidate(candidate_id: str, status: str, validation_result: dict):
    """Update detection candidate with validation results."""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE detection_candidates SET status = %s, validation_result = %s WHERE id = %s",
                (status, json.dumps(validation_result), candidate_id)
            )
        conn.commit()
    except Exception as e:
        print(f"Candidate update failed: {e}")
    finally:
        conn.close()


def _create_detection_rule(candidate_id, technique_id, sigma_yaml, tp_rate, fp_rate, investigations_matched):
    """Create a detection rule from an approved candidate."""
    conn = _get_db()
    try:
        # Extract title from YAML
        rule_name = f"HYDRA-{technique_id}"
        if HAS_YAML:
            try:
                parsed = yaml.safe_load(sigma_yaml)
                if isinstance(parsed, dict) and "title" in parsed:
                    rule_name = parsed["title"]
            except Exception:
                pass

        with conn.cursor() as cur:
            # Get next version for this technique
            cur.execute(
                "SELECT COALESCE(MAX(rule_version), 0) + 1 FROM detection_rules WHERE technique_id = %s",
                (technique_id,)
            )
            next_version = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO detection_rules
                (candidate_id, technique_id, rule_name, rule_version, sigma_yaml,
                 tp_rate, fp_rate, investigations_matched)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (technique_id, rule_version) DO NOTHING
                RETURNING id
            """, (
                candidate_id, technique_id, rule_name, next_version, sigma_yaml,
                tp_rate, fp_rate, investigations_matched
            ))
            row = cur.fetchone()
            rule_id = str(row[0]) if row else None
        conn.commit()
        return rule_id
    except Exception as e:
        print(f"Rule creation failed: {e}")
        return None
    finally:
        conn.close()
