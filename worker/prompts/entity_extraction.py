"""LLM prompt template for structured entity extraction from investigation output."""

import json

ENTITY_EXTRACTION_SYSTEM_PROMPT = """You are a security analyst extracting structured threat intelligence entities from investigation output.

Extract ALL observable entities (IOCs) and their relationships from the investigation results.

Return a JSON object with exactly this structure:
{
  "entities": [
    {
      "type": "<ip|domain|file_hash|url|user|device|process|email>",
      "value": "<the raw value>",
      "role": "<source|destination|attacker|victim|indicator|artifact|infrastructure|target>",
      "context": "<brief description of how this entity appears in the investigation>",
      "mitre_technique": "<MITRE ATT&CK technique ID if applicable, e.g. T1110.003, or null>"
    }
  ],
  "edges": [
    {
      "source": {"type": "<entity_type>", "value": "<entity_value>"},
      "target": {"type": "<entity_type>", "value": "<entity_value>"},
      "edge_type": "<communicates_with|resolved_to|logged_into|executed|downloaded|contains|parent_of|accessed|sent_to|received_from|associated_with>",
      "mitre_technique": "<MITRE technique ID or null>"
    }
  ]
}

Rules:
- Extract ALL IPs, domains, file hashes, URLs, usernames, device names, process names, and emails
- Assign roles based on context (attacker vs victim, source vs destination)
- Create edges for observed relationships (IP communicates_with IP, user logged_into device, etc.)
- Include MITRE ATT&CK technique IDs where the behavior maps to a known technique
- If no entities are found, return {"entities": [], "edges": []}
- Return ONLY valid JSON, no markdown or explanation"""


def build_entity_extraction_prompt(investigation_output: str, task_type: str, max_chars: int = 3000) -> str:
    """Build user prompt for entity extraction, truncating to fit Qwen 1.5B context.

    Args:
        investigation_output: The raw stdout/JSON from the sandbox execution
        task_type: The investigation type (brute_force, ransomware, etc.)
        max_chars: Max characters for the investigation output (default 3000 for Qwen 1.5B)

    Returns:
        Formatted user prompt string
    """
    # Truncate investigation output for context window
    if len(investigation_output) > max_chars:
        investigation_output = investigation_output[:max_chars] + "\n... [truncated]"

    return (
        f"Investigation type: {task_type}\n\n"
        f"Investigation output:\n{investigation_output}\n\n"
        "Extract all entities and their relationships from this investigation output. "
        "Return ONLY a JSON object with 'entities' and 'edges' arrays."
    )
