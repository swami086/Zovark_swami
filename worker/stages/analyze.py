"""
Stage 2: ANALYZE — Code Generation

This is the ONLY module that should contain LLM code generation calls.
All code-gen LLM interactions are routed through this module.

Three paths (in priority order):
  1. FAST_FILL  → regex stub, no LLM, no template (~5ms)
  2. Template   → fill_skill_parameters + render_skill_template (LLM for params only)
  3. LLM Gen    → full generate_code via LLM (~5 min on RTX 3050)

Usage:
    from stages.analyze import analyze_alert
    result: AnalyzeOutput = await analyze_alert(ingest_output)
"""
import os
import re
import json
import time
from typing import Optional

from stages import AnalyzeOutput, IngestOutput

# Detect mode once at import time
FAST_FILL = os.environ.get("HYDRA_FAST_FILL", "false").lower() == "true"


def generate_fast_fill_stub(siem_event: dict, task_type: str) -> AnalyzeOutput:
    """
    Path 1: Generate a regex-based IOC extraction script.
    No LLM call. No template. Pure Python string construction.
    Completes in <5ms.
    """
    raw_log = (siem_event.get("raw_log", "") or "").replace('\\', '\\\\').replace('"""', '\\"\\"\\"')

    code = (
        'import re, json\n\n'
        f'raw_log = """{raw_log}"""\n\n'
        'ips = list(set(re.findall(r"\\d+\\.\\d+\\.\\d+\\.\\d+", raw_log)))\n'
        'users = list(set(re.findall(r"User[=:]\\s*(\\S+)", raw_log)))\n'
        'hashes = list(set(re.findall(r"\\b[a-fA-F0-9]{32,64}\\b", raw_log)))\n'
        'domains = list(set(re.findall(r"(?:https?://|DNS query: )([\\w.-]+)", raw_log)))\n'
        'iocs = []\n'
        'for ip in ips: iocs.append({"type":"ipv4","value":ip,"confidence":"high"})\n'
        'for u in users: iocs.append({"type":"username","value":u,"confidence":"high"})\n'
        'for h in hashes: iocs.append({"type":"hash","value":h,"confidence":"medium"})\n'
        'for d in domains: iocs.append({"type":"domain","value":d,"confidence":"high"})\n'
        f'print(json.dumps({{"findings":[{{"title":"Alert analyzed","details":"{task_type}"}}],'
        f'"iocs":iocs,"risk_score":75,"recommendations":["Investigate further"]}}))\n'
    )

    return AnalyzeOutput(
        code=code,
        source="fast_fill",
        preflight_passed=True,
        generation_ms=0,
    )


def fill_parameters_fast(skill_params: list, siem_event: dict) -> dict:
    """
    Fast parameter filling from SIEM event fields.
    No LLM call. Direct field mapping.
    """
    defaults = {p["name"]: p.get("default") for p in skill_params}
    filled = dict(defaults)

    field_map = {
        "log_data": siem_event.get("raw_log", ""),
        "raw_log": siem_event.get("raw_log", ""),
        "source_ip": siem_event.get("source_ip", "10.0.0.1"),
        "src_ip": siem_event.get("source_ip", "10.0.0.1"),
        "destination_ip": siem_event.get("destination_ip", "10.0.0.2"),
        "dst_ip": siem_event.get("destination_ip", "10.0.0.2"),
        "hostname": siem_event.get("hostname", "UNKNOWN-HOST"),
        "username": siem_event.get("username", "unknown_user"),
        "rule_name": siem_event.get("rule_name", ""),
        "title": siem_event.get("title", ""),
    }

    for k in filled:
        if k in field_map and field_map[k]:
            filled[k] = field_map[k]
        elif k in siem_event:
            filled[k] = siem_event[k]

    if "log_data" in filled and not filled["log_data"] and siem_event.get("raw_log"):
        filled["log_data"] = siem_event["raw_log"]

    return filled


def preflight_check(code: str) -> tuple:
    """
    Run preflight validation on generated code.
    Returns (passed: bool, fixed_code: str, fixes: list).
    No LLM call. <100ms.
    """
    from validation.preflight import preflight_validate, auto_fix_code

    fixed_code, fixes = auto_fix_code(code)
    is_valid, error_or_cleaned, warnings = preflight_validate(fixed_code)

    if is_valid and error_or_cleaned:
        # preflight_validate returned cleaned code
        fixed_code = error_or_cleaned

    return is_valid, fixed_code, fixes + warnings


async def analyze_alert(ingest: IngestOutput) -> AnalyzeOutput:
    """
    Main entry point for Stage 2.
    Routes to the appropriate code generation path.

    This function is the ONLY place that decides whether to call the LLM.
    """
    siem_event = ingest.siem_event
    task_type = ingest.task_type

    # Path 1: FAST_FILL — no LLM at all
    if FAST_FILL:
        return generate_fast_fill_stub(siem_event, task_type)

    # Path 2: Template — LLM only for parameter filling
    if ingest.skill_template and ingest.skill_params:
        t0 = time.time()

        if FAST_FILL:
            # Should not reach here, but safety net
            filled = fill_parameters_fast(ingest.skill_params, siem_event)
            tokens_in, tokens_out = 0, 0
        else:
            # Call LLM to fill parameters
            # This delegates to the existing fill_skill_parameters activity
            # which is called from the workflow, not directly here.
            # This module documents the contract; the workflow orchestrates the calls.
            return AnalyzeOutput(
                code="",  # Workflow will call fill_skill_parameters + render_skill_template
                source="template",
                skill_id=ingest.skill_id,
                generation_ms=0,
            )

    # Path 3: LLM code generation
    # The workflow calls generate_code activity directly.
    # This module documents the contract; the workflow orchestrates.
    return AnalyzeOutput(
        code="",  # Workflow will call generate_code
        source="llm",
        generation_ms=0,
    )
