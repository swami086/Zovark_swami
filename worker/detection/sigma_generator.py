"""Sigma rule generator — LLM-powered detection rule generation.

Uses the reasoning model tier to generate Sigma YAML rules
from attack pattern candidates and MITRE technique descriptions.
"""

import os
import time
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity

from model_config import get_tier_config
from prompt_registry import get_version
from llm_logger import log_llm_call

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


SIGMA_SYSTEM_PROMPT = (
    "You are a detection engineer. Generate a Sigma detection rule in YAML format. "
    "The rule MUST have these required fields: title, status (test), level (medium/high/critical), "
    "logsource (with category or product), detection (with selection and condition), description, "
    "and tags (MITRE ATT&CK technique IDs). "
    "IMPORTANT: Do NOT include any real tenant-specific data (no real IPs, usernames, hostnames). "
    "Use generic patterns and field references. "
    "Output ONLY valid YAML, no markdown fences or explanations."
)


@activity.defn
async def generate_sigma_rule(data: dict) -> dict:
    """Generate a Sigma rule from a detection candidate.

    Input: {candidate_id, technique_id, pattern_description, entity_types, edge_patterns}
    Returns: {candidate_id, sigma_yaml, valid, error}
    """
    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
    tier_config = get_tier_config("generate_sigma_rule")
    llm_model = tier_config["model"]

    candidate_id = data.get("candidate_id")
    technique_id = data.get("technique_id", "")
    pattern_description = data.get("pattern_description", "")
    entity_types = data.get("entity_types", [])
    edge_patterns = data.get("edge_patterns", [])

    # Fetch MITRE technique description
    technique_desc = ""
    example_summaries = []
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get technique description
            cur.execute(
                "SELECT name, description FROM mitre_techniques WHERE technique_id = %s",
                (technique_id,)
            )
            row = cur.fetchone()
            if row:
                technique_desc = f"{row['name']}: {row['description'][:500]}"

            # Get example investigation summaries
            cur.execute("""
                SELECT i.summary
                FROM investigations i
                JOIN entity_observations eo ON eo.investigation_id = i.id
                WHERE eo.mitre_technique = %s
                  AND i.summary IS NOT NULL
                  AND i.verdict IN ('true_positive', 'suspicious')
                LIMIT 3
            """, (technique_id,))
            example_summaries = [r["summary"][:300] for r in cur.fetchall()]
    finally:
        conn.close()

    user_prompt = (
        f"Generate a Sigma detection rule for MITRE ATT&CK technique {technique_id}.\n\n"
        f"Technique: {technique_desc}\n\n"
        f"Pattern: {pattern_description}\n"
        f"Entity types involved: {', '.join(entity_types)}\n"
        f"Edge patterns: {', '.join(edge_patterns) if edge_patterns else 'none'}\n\n"
    )
    if example_summaries:
        user_prompt += "Example investigation summaries:\n"
        for i, s in enumerate(example_summaries, 1):
            user_prompt += f"{i}. {s}\n"
        user_prompt += "\n"
    user_prompt += "Generate a Sigma YAML rule. Output ONLY valid YAML."

    start_time = time.time()
    sigma_yaml = ""
    valid = False
    error = None

    try:
        # Update candidate status
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE detection_candidates SET status = 'generating' WHERE id = %s", (candidate_id,))
            conn.commit()
        finally:
            conn.close()

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                litellm_url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": llm_model,
                    "messages": [
                        {"role": "system", "content": SIGMA_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": tier_config["temperature"],
                    "max_tokens": tier_config["max_tokens"],
                },
            )
            resp.raise_for_status()
            result = resp.json()
            usage = result.get("usage", {})
            sigma_yaml = result["choices"][0]["message"]["content"].strip()

            # Strip markdown fences if present
            if sigma_yaml.startswith("```yaml"):
                sigma_yaml = sigma_yaml[7:]
            if sigma_yaml.startswith("```"):
                sigma_yaml = sigma_yaml[3:]
            if sigma_yaml.endswith("```"):
                sigma_yaml = sigma_yaml[:-3]
            sigma_yaml = sigma_yaml.strip()

            latency_ms = int((time.time() - start_time) * 1000)

            log_llm_call(
                activity_name="generate_sigma_rule",
                model_tier=tier_config["tier"],
                model_id=llm_model,
                prompt_name="sigma_generation",
                prompt_version=get_version("sigma_generation"),
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
                latency_ms=latency_ms,
                temperature=tier_config["temperature"],
                max_tokens=tier_config["max_tokens"],
            )

            # Basic YAML validation
            if HAS_YAML:
                try:
                    parsed = yaml.safe_load(sigma_yaml)
                    if isinstance(parsed, dict) and "title" in parsed and "detection" in parsed:
                        valid = True
                    else:
                        error = "Missing required Sigma fields (title, detection)"
                except yaml.YAMLError as e:
                    error = f"Invalid YAML: {e}"
            else:
                # Basic string validation without pyyaml
                valid = "title:" in sigma_yaml and "detection:" in sigma_yaml
                if not valid:
                    error = "Missing title or detection fields"

    except Exception as e:
        error = str(e)
        latency_ms = int((time.time() - start_time) * 1000)
        log_llm_call(
            activity_name="generate_sigma_rule",
            model_tier=tier_config["tier"],
            model_id=llm_model,
            prompt_name="sigma_generation",
            latency_ms=latency_ms,
            status="error",
            error_message=str(e),
        )

    # Store result in candidate
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            new_status = "validating" if valid else "rejected"
            cur.execute(
                "UPDATE detection_candidates SET sigma_rule = %s, status = %s WHERE id = %s",
                (sigma_yaml if sigma_yaml else None, new_status, candidate_id)
            )
        conn.commit()
    finally:
        conn.close()

    print(f"Sigma generation for {technique_id}: valid={valid}, error={error}")
    return {
        "candidate_id": candidate_id,
        "sigma_yaml": sigma_yaml,
        "valid": valid,
        "error": error,
    }
