"""
Investigation prompt template with memory context injection.
Registers with existing prompt_registry.py via get_version() SHA256 pattern.
JSON enforcement is IN THE PROMPT TEXT — NOT via API response_format parameter.
"""

from security.prompt_sanitizer import wrap_untrusted_data

INVESTIGATION_PROMPT_V1 = """You are a SOC analyst investigating a security alert.

ALERT CONTEXT:
Alert Type: {alert_type}
Source: {source}
Timestamp: {timestamp}
Raw Data:
{raw_data}

{memory_section}

YOUR TASK:
Analyze this alert and produce investigation findings. You MUST respond with
ONLY valid JSON (no markdown, no code fences, no explanation outside the JSON).

Required JSON structure:
{{
  "findings": ["string describing each finding"],
  "confidence": <float 0.0-1.0>,
  "entities": [
    {{"type": "ip|domain|file_hash|user|process|url|email", "value": "...", "context": "..."}}
  ],
  "verdict": "malicious|suspicious|benign|insufficient_data",
  "recommended_actions": ["action1", "action2"],
  "reasoning": "Brief explanation of your conclusion"
}}

IMPORTANT: Output ONLY the JSON object. No other text."""


def build_investigation_prompt(alert, memory=None):
    """Build prompt with optional memory enrichment."""
    memory_section = _format_memory(memory) if memory else "PRIOR INTELLIGENCE: No prior investigations found for these indicators."

    safe_alert, _ = wrap_untrusted_data(str(alert.get('input', alert.get('raw_data', '')))[:2000], "alert_data")

    return INVESTIGATION_PROMPT_V1.format(
        alert_type=alert.get('task_type', alert.get('type', 'unknown')),
        source=alert.get('source', 'SIEM'),
        timestamp=alert.get('timestamp', 'N/A'),
        raw_data=safe_alert,
        memory_section=memory_section
    )


def _format_memory(memory):
    """Format memory context for prompt injection."""
    lines = ["PRIOR INTELLIGENCE FROM INVESTIGATION MEMORY:"]

    if memory.get('exact_matches'):
        lines.append("\nEXACT MATCHES (High Confidence — same indicator seen before):")
        for m in memory['exact_matches']:
            lines.append(
                f"  - {m['type'].upper()} {m['entity']}: "
                f"Previously concluded '{m['conclusion']}' "
                f"(confidence: {m['confidence']:.2f}, "
                f"investigation: {m['investigation_id']}, "
                f"seen: {m['seen_at']})"
            )

    if memory.get('similar_entities'):
        lines.append("\nSIMILAR INDICATORS (Lower Confidence — review recommended):")
        for m in memory['similar_entities']:
            lines.append(
                f"  - {m['type'].upper()} {m['entity']} similar to {m['similar_to']}: "
                f"Prior conclusion '{m['conclusion']}' "
                f"(adjusted confidence: {m['confidence']:.2f}, "
                f"similarity distance: {m['distance']:.4f})"
            )

    if not memory.get('exact_matches') and not memory.get('similar_entities'):
        lines.append("  No relevant prior investigations found.")

    return "\n".join(lines)
