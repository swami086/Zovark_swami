"""
Stage 4: ASSESS — Generate verdict and investigation summary.
LLM calls: entity extraction (optional), FP analysis (optional).

This is one of TWO files that call the LLM (the other is Stage 2 ANALYZE).
All LLM verdict/summary calls are contained HERE.

Self-contained: imports httpx, psycopg2 directly.
Does NOT import from _legacy_activities.py or intelligence/fp_analyzer.py.
"""
import os
import re
import json
import time
from typing import List, Dict
from dataclasses import asdict

import httpx

from temporalio import activity
from stages import AssessOutput
from stages.llm_gateway import llm_call, MODEL_CODE
from stages.model_router import get_model_config
from stages.output_validator import validate_investigation_output, safe_default_output
from stages.mitre_mapping import get_mitre_techniques

FAST_FILL = os.environ.get("ZOVARK_FAST_FILL", "false").lower() == "true"
ZOVARK_LLM_ENDPOINT = os.environ.get("ZOVARK_LLM_ENDPOINT", "http://host.docker.internal:11434/v1/chat/completions")
ZOVARK_LLM_KEY = os.environ.get("ZOVARK_LLM_KEY", "zovark-llm-key-2026")


# --- Verdict derivation ---
def _derive_verdict(risk_score: int, ioc_count: int, finding_count: int) -> str:
    # Error state: safety wrapper produced risk=0 with a single error finding
    if risk_score == 0 and finding_count <= 1:
        return "error"
    # Benign: unconditional at low risk
    if risk_score <= 35:
        return "benign"
    # True positive: high confidence
    if risk_score >= 80 and ioc_count >= 3:
        return "true_positive"
    if risk_score >= 70:
        return "true_positive"
    # Suspicious: moderate signals (covers the 36-49 dead zone)
    if risk_score >= 50:
        return "suspicious"
    if risk_score >= 36 and finding_count >= 1:
        return "suspicious"
    # Benign: low risk with no findings
    if finding_count == 0 and ioc_count == 0:
        return "benign"
    # Last resort — should be very rare
    return "inconclusive"


def _severity_from_risk(risk_score: int) -> str:
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    return "informational"


# --- Template summary (no LLM) ---
def _template_summary(task_type: str, findings: list, iocs: list, risk_score: int) -> str:
    """Generate a memory summary without LLM."""
    ioc_types = set()
    for ioc in iocs:
        if isinstance(ioc, dict):
            ioc_types.add(ioc.get("type", "unknown"))
    return (
        f"Investigated {task_type} alert. "
        f"Found {len(findings)} findings and {len(iocs)} IOCs ({', '.join(ioc_types) or 'none'}). "
        f"Risk score: {risk_score}."
    )


# --- LLM summary (optional) ---
async def _llm_summary(stdout: str, task_type: str, task_id: str = "", tenant_id: str = "") -> str:
    """Call LLM to generate a 2-3 sentence investigation summary."""
    try:
        summary_config = get_model_config(severity="low", task_type=task_type)
        summary_config.update({"model": MODEL_CODE, "temperature": 0.1, "max_tokens": 200})
        result = await llm_call(
            prompt=stdout[:2000],
            system_prompt="Summarize this investigation in 2-3 sentences.",
            model_config=summary_config,
            task_id=task_id,
            stage="assess",
            task_type=task_type,
            tenant_id=tenant_id,
            timeout=15.0,  # Short — template summary fallback is fine
        )
        return result["content"]
    except Exception as e:
        print(f"LLM summary failed (non-fatal): {type(e).__name__}: {e}")
        return ""


# --- Comprehensive IOC extraction ---
def _is_valid_ioc_ip(ip: str) -> bool:
    """Check if IP is valid and not a boring internal/broadcast address."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums):
            return False
        if ip in ('0.0.0.0', '255.255.255.255', '127.0.0.1'):
            return False
        if nums[0] == 0 or nums[0] >= 224:
            return False
        return True
    except (ValueError, IndexError):
        return False


def _looks_like_uuid(h: str) -> bool:
    """Check if a 32-char hex string is likely a UUID."""
    if len(h) == 32:
        return h[12] == '4' and h[16] in '89ab'
    return False


def _snippet_around(text: str, value: str, context_chars: int = 30) -> str:
    """Return a snippet of text surrounding the first occurrence of value."""
    match_pos = text.find(value)
    if match_pos >= 0:
        start = max(0, match_pos - context_chars)
        end = min(len(text), match_pos + len(value) + context_chars)
        return text[start:end]
    return value


def _raw_text_evidence(combined_text: str, value: str) -> list:
    """Build evidence_refs for an IOC found via regex in raw text."""
    snippet = _snippet_around(combined_text, value)
    return [{"source": "raw_log", "raw_text": snippet}]


def _extract_iocs_from_signals(siem_event: dict, stdout: str, prompt: str = "") -> list:
    """Extract IOCs from SIEM data and sandbox output, with evidence_refs."""
    iocs = []
    seen = set()

    combined_text = f"{stdout} {prompt}"
    if isinstance(siem_event, dict):
        combined_text += f" {siem_event.get('raw_log', '')}"
        combined_text += f" {siem_event.get('title', '')}"
        combined_text += f" {siem_event.get('rule_name', '')}"

    # Structured SIEM fields (highest confidence)
    if isinstance(siem_event, dict):
        for field in ('source_ip', 'src_ip', 'attacker_ip', 'remote_ip'):
            ip = siem_event.get(field, '')
            if ip and _is_valid_ioc_ip(ip) and ip not in seen:
                iocs.append({
                    "type": "ipv4", "value": ip, "context": f"{field} from SIEM event",
                    "evidence_refs": [{"source": f"siem_event.{field}", "raw_text": ip, "field_path": f"siem_event.{field}"}],
                })
                seen.add(ip)
        for field in ('destination_ip', 'dst_ip', 'dest_ip', 'target_ip'):
            ip = siem_event.get(field, '')
            if ip and _is_valid_ioc_ip(ip) and ip not in seen:
                iocs.append({
                    "type": "ipv4", "value": ip, "context": f"{field} from SIEM event",
                    "evidence_refs": [{"source": f"siem_event.{field}", "raw_text": ip, "field_path": f"siem_event.{field}"}],
                })
                seen.add(ip)
        for field in ('username', 'user', 'account', 'email', 'src_user', 'target_user'):
            val = siem_event.get(field, '')
            if val and '@' in val and val not in seen:
                iocs.append({
                    "type": "email", "value": val, "context": f"{field} from SIEM event",
                    "evidence_refs": [{"source": f"siem_event.{field}", "raw_text": val, "field_path": f"siem_event.{field}"}],
                })
                seen.add(val)
            elif val and val not in seen and val not in ('root', 'admin', 'system', 'unknown', 'N/A', '-', 'attacker'):
                iocs.append({
                    "type": "username", "value": val, "context": f"{field} from SIEM event",
                    "evidence_refs": [{"source": f"siem_event.{field}", "raw_text": val, "field_path": f"siem_event.{field}"}],
                })
                seen.add(val)

    # IPs from raw text
    for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', combined_text):
        if ip not in seen and _is_valid_ioc_ip(ip):
            iocs.append({
                "type": "ipv4", "value": ip, "context": "extracted from log/analysis",
                "evidence_refs": _raw_text_evidence(combined_text, ip),
            })
            seen.add(ip)

    # URLs
    for url in re.findall(r'(https?://[^\s<>"\')\]]+)', combined_text):
        url = url.rstrip('.,;:')
        if url not in seen and len(url) > 10:
            iocs.append({
                "type": "url", "value": url[:200], "context": "extracted from log/analysis",
                "evidence_refs": _raw_text_evidence(combined_text, url),
            })
            seen.add(url)

    # Emails
    for email in re.findall(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', combined_text):
        if email not in seen and not email.endswith('.local'):
            iocs.append({
                "type": "email", "value": email, "context": "extracted from log/analysis",
                "evidence_refs": _raw_text_evidence(combined_text, email),
            })
            seen.add(email)

    # File hashes
    for h in re.findall(r'\b([a-fA-F0-9]{64})\b', combined_text):
        if h.lower() not in seen:
            iocs.append({
                "type": "sha256", "value": h.lower(), "context": "hash extracted from log/analysis",
                "evidence_refs": _raw_text_evidence(combined_text, h),
            })
            seen.add(h.lower())
    for h in re.findall(r'\b([a-fA-F0-9]{40})\b', combined_text):
        if h.lower() not in seen:
            iocs.append({
                "type": "sha1", "value": h.lower(), "context": "hash extracted from log/analysis",
                "evidence_refs": _raw_text_evidence(combined_text, h),
            })
            seen.add(h.lower())
    for h in re.findall(r'\b([a-fA-F0-9]{32})\b', combined_text):
        if h.lower() not in seen and not _looks_like_uuid(h):
            iocs.append({
                "type": "md5", "value": h.lower(), "context": "hash extracted from log/analysis",
                "evidence_refs": _raw_text_evidence(combined_text, h),
            })
            seen.add(h.lower())

    # Domains
    domain_tlds = r'(?:com|net|org|io|xyz|ru|cn|tk|info|biz|top|cc|pw|ws|club|site|online|live|me|co|op)'
    for domain in re.findall(rf'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?)*\.{domain_tlds})\b', combined_text):
        if domain.lower() not in seen and len(domain) > 4:
            iocs.append({
                "type": "domain", "value": domain.lower(), "context": "domain extracted from log/analysis",
                "evidence_refs": _raw_text_evidence(combined_text, domain),
            })
            seen.add(domain.lower())

    # CVE IDs
    for cve in re.findall(r'\b(CVE-\d{4}-\d{4,})\b', combined_text, re.IGNORECASE):
        if cve.upper() not in seen:
            iocs.append({
                "type": "cve", "value": cve.upper(), "context": "CVE reference",
                "evidence_refs": _raw_text_evidence(combined_text, cve),
            })
            seen.add(cve.upper())

    return iocs


# --- FP confidence (simple rules, no LLM) ---
def _fp_confidence(risk_score: int, ioc_count: int) -> float:
    """Rule-based FP confidence. Higher = more likely false positive."""
    if risk_score >= 80 and ioc_count >= 3:
        return 0.1  # Very likely real
    elif risk_score >= 60:
        return 0.3
    elif risk_score >= 40:
        return 0.5
    elif ioc_count == 0:
        return 0.8  # Likely FP
    return 0.6


# --- Validation failure logging ---
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")


def _log_validation_failure(task_id: str, tenant_id: str, task_type: str, error_msg: str):
    """Log validation failure to llm_audit_log (best-effort, never raises)."""
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO llm_audit_log
                       (tenant_id, task_id, stage, task_type, model_name, status, error_message, created_at)
                       VALUES (%s, %s, 'assess', %s, 'output_validator', 'validation_failed', %s, NOW())""",
                    (tenant_id, task_id, task_type, error_msg),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        # Never let audit logging break the pipeline
        print(f"Validation failure logging failed (non-fatal): {e}")


# --- Main entry point ---
@activity.defn
async def assess_results(data: dict) -> dict:
    """
    Stage 4: Generate verdict and investigation summary.

    FAST_FILL: template verdict based on IOC count (no LLM).
    Normal: optional LLM summary + rules-based FP analysis.

    Input: ExecuteOutput fields + task metadata
    Returns: dict (serializable AssessOutput fields)
    """
    task_id = data.get("task_id", "")
    tenant_id = data.get("tenant_id", "")
    stdout = data.get("stdout", "")
    iocs = data.get("iocs", [])
    findings = data.get("findings", [])
    risk_score = data.get("risk_score", 0)
    recommendations = data.get("recommendations", [])
    task_type = data.get("task_type", "")

    # --- Schema validation of sandbox output ---
    # Validate the data coming from execute stage (findings, iocs, risk_score, recommendations)
    sandbox_output = {
        "findings": findings,
        "iocs": iocs,
        "risk_score": risk_score,
        "recommendations": recommendations,
    }
    is_valid, validation_error = validate_investigation_output(sandbox_output)
    if not is_valid:
        activity.logger.warning(
            f"Sandbox output validation failed for task {task_id}: {validation_error}"
        )
        # Log validation failure to llm_audit_log (best-effort)
        _log_validation_failure(task_id, tenant_id, task_type, validation_error)
        # Use safe defaults — NEVER let invalid output reach the dashboard
        defaults = safe_default_output()
        findings = defaults["findings"]
        iocs = defaults["iocs"]
        risk_score = defaults["risk_score"]
        recommendations = defaults["recommendations"]

    # --- Web attack signal boost ---
    # If raw SIEM data contains obvious attack patterns, boost risk score
    # regardless of which template ran. This handles cross-category mismatches
    # (e.g., SQLi alert categorized as data_exfil).
    siem_event = data.get("siem_event", {})
    if isinstance(siem_event, dict):
        raw_log = siem_event.get("raw_log", "")
        siem_title = siem_event.get("title", "")
        siem_rule = siem_event.get("rule_name", "")
    else:
        raw_log = siem_title = siem_rule = ""
    combined_signal = f"{raw_log} {siem_title} {siem_rule} {stdout}".lower()

    attack_signals = [
        (r"(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|;.*--|\bsleep\s*\(|benchmark\s*\(|sqli|sql.?inject)", "SQL injection"),
        (r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|\bxss\b", "Cross-site scripting"),
        (r"\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|path.?traversal|directory.?traversal", "Path traversal"),
        (r"admin.*bypass|auth.*bypass|broken.*auth|forced.?browsing|idor|bola|unauthorized.*access", "Auth bypass"),
        (r"command.?injection|cmd.?inject|;\s*cat\s|;\s*ls\s|`.*`|\$\(.*\)|%0a|rce\b", "Command injection"),
        (r"ssrf|server.?side.?request|localhost.*redirect|127\.0\.0\.1.*access", "SSRF"),
        (r"file.?upload|unrestricted.?upload|webshell|\.php\b.*upload|\.jsp\b.*upload", "File upload attack"),
    ]
    attack_boost = 0
    attack_types_found = []
    for pattern, attack_name in attack_signals:
        if re.search(pattern, combined_signal, re.IGNORECASE):
            attack_boost += 45
            attack_types_found.append(attack_name)
    if attack_boost > 0:
        risk_score = min(100, risk_score + attack_boost)
        if not any(attack_types_found[0].lower() in str(f).lower() for f in findings):
            findings.append({"title": f"Attack Signal: {', '.join(attack_types_found)}",
                             "details": f"SIEM data contains indicators of {', '.join(attack_types_found)}"})
    # --- Comprehensive IOC extraction from SIEM + sandbox output ---
    extracted_iocs = _extract_iocs_from_signals(siem_event, stdout)
    existing_by_value = {}
    for i in iocs:
        if isinstance(i, dict):
            existing_by_value[i.get("value", "")] = i
    for new_ioc in extracted_iocs:
        val = new_ioc["value"]
        if val in existing_by_value:
            # Enrich existing IOC with evidence_refs from extraction
            existing_ioc = existing_by_value[val]
            if "evidence_refs" not in existing_ioc:
                existing_ioc["evidence_refs"] = new_ioc.get("evidence_refs", [])
        else:
            iocs.append(new_ioc)
            existing_by_value[val] = new_ioc

    # Template attack risk floor: if the alert matched a known attack template
    # (Path A) but the LLM under-scored it, ensure risk >= 70.
    # Only applies when risk is in the ambiguous 36-69 range — doesn't override
    # genuinely benign verdicts (<=35) or already-high scores (>=70).
    from stages.ingest import _has_attack_indicators
    siem_rule_name = siem_event.get("rule_name", "") if isinstance(siem_event, dict) else ""
    siem_title_val = siem_event.get("title", "") if isinstance(siem_event, dict) else ""
    if _has_attack_indicators(task_type, siem_rule_name, siem_title_val):
        if 36 <= risk_score < 70:
            activity.logger.info(f"Boosting template-matched attack from risk {risk_score} to 70")
            risk_score = 70

    # Check for verdict_override from safety wrapper (crashed Path C code)
    verdict_override = data.get("verdict_override", "")
    if verdict_override == "error":
        verdict = "error"
    else:
        verdict = _derive_verdict(risk_score, len(iocs), len(findings))
    severity = _severity_from_risk(risk_score)
    fp_conf = _fp_confidence(risk_score, len(iocs))

    # If validation failed, override verdict
    if not is_valid:
        verdict = "needs_manual_review"

    # Summary
    if FAST_FILL:
        summary = _template_summary(task_type, findings, iocs, risk_score)
    else:
        summary = await _llm_summary(stdout, task_type, task_id=task_id, tenant_id=tenant_id)
        if not summary:
            summary = _template_summary(task_type, findings, iocs, risk_score)

    result = AssessOutput(
        verdict=verdict,
        risk_score=risk_score,
        severity=severity,
        confidence=1.0 - fp_conf,
        false_positive_confidence=fp_conf,
        recommendations=recommendations,
        memory_summary=summary,
    )

    out = asdict(result)
    # Include enriched iocs/findings so they override executed values in store merge
    out["iocs"] = iocs
    out["findings"] = findings
    out["mitre_attack"] = get_mitre_techniques(task_type)
    out["investigation_metadata"] = {
        "pipeline_version": "v2",
        "schema_validated": is_valid,
    }
    return out
