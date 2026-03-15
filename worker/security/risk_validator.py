"""Independent heuristic validation of LLM-derived risk scores."""
import re
from typing import List

HIGH_RISK_INDICATORS = {
    r"cobalt\s*strike": 30, r"mimikatz": 30, r"metasploit": 25,
    r"reverse\s*shell": 30, r"c2\s*(beacon|server|channel)": 25,
    r"lateral\s*movement": 20, r"privilege\s*escalation": 25,
    r"credential\s*dump": 25, r"data\s*exfil": 25, r"ransomware": 30,
    r"psexec": 20, r"powershell.*-enc": 20, r"powershell.*downloadstring": 25,
    r"certutil.*urlcache": 20, r"bitsadmin.*transfer": 20,
}
HIGH_RISK_TECHNIQUES = {
    "T1059.001", "T1003", "T1078", "T1021", "T1053",
    "T1047", "T1569", "T1548", "T1134", "T1055",
}


def compute_heuristic_risk(alert_data, entities, output, techniques):
    score = {"critical": 40, "high": 30, "medium": 15, "low": 5}.get(
        (alert_data.get("severity") or "").lower(), 10)
    text = " ".join([str(alert_data.get("description", "")),
        str(alert_data.get("alert_name", "")), output]).lower()
    for p, pts in HIGH_RISK_INDICATORS.items():
        if re.search(p, text, re.I):
            score += pts
    for t in techniques:
        if t in HIGH_RISK_TECHNIQUES:
            score += 15
    types = [e.get("type", "") for e in entities]
    if types.count("file_hash") >= 2:
        score += 10
    if types.count("ip") >= 3:
        score += 10
    for e in entities:
        ts = e.get("threat_score", 0)
        if ts > 70:
            score += 15
        elif ts > 40:
            score += 5
    return min(score, 100)


def validate_risk_score(llm_score, alert_data, entities, output, techniques, threshold=30):
    heuristic = compute_heuristic_risk(alert_data, entities, output, techniques)
    final = llm_score
    overridden = False
    reason = None
    if heuristic - llm_score > threshold:
        final = heuristic
        overridden = True
        reason = f"LLM ({llm_score}) suppressed below heuristic ({heuristic})"
    sev = ("critical" if final >= 80 else "high" if final >= 60
           else "medium" if final >= 40 else "low" if final >= 20
           else "informational")
    return {
        "final_risk_score": final,
        "final_severity": sev,
        "llm_score": llm_score,
        "heuristic_score": heuristic,
        "score_overridden": overridden,
        "override_reason": reason,
    }
