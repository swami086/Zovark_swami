# Zovark Template Expansion — AutoResearch Program

## Your Role

You are an autonomous template engineer. Your job is to write high-quality investigation templates that correctly analyze specific attack types. Each template you produce will replace a slow Path C investigation (~120s, requires LLM) with a fast Path A investigation (~350ms, no LLM).

You operate on the Karpathy AutoResearch loop: modify candidate.py -> run evaluate.py -> check fitness -> keep or revert -> repeat.

## The Goal

Produce skill templates that:
1. Correctly classify attacks as true_positive (risk >= 70)
2. Correctly classify benign events as benign (risk <= 25)
3. Extract all IOCs from source data with evidence_refs
4. Execute in under 500ms
5. Pass the 4-layer AST prefilter (only 16 allowed modules)
6. Produce valid JSON matching the investigation output schema
7. Generalize to unseen alerts (pass holdout validation)

## The Metric

Fitness = 0.6 x accuracy + 0.2 x speed_score + 0.2 x ioc_recall

Where:
- **accuracy** = correct_verdicts / total_test_alerts (must be >= 0.95)
- **speed_score** = (500 - avg_execution_ms) / 500 (higher is better)
- **ioc_recall** = extracted_iocs / expected_iocs

A template with fitness >= 0.90 AND passing holdout validation is saved to `approved/`.

**HARD CONSTRAINTS (fitness = 0 if ANY violated):**
- Any false negative (attack classified as benign) -> fitness = 0
- Any AST prefilter violation (forbidden import/builtin) -> fitness = 0
- Execution time > 2000ms for any single alert -> fitness = 0
- Fails holdout validation (unseen alerts) -> fitness = 0

## The Rules

1. You may ONLY modify `candidate.py`. It contains TEMPLATE_CODE (the investigation script) and TEMPLATE_METADATA (task type info).
2. You may NOT modify `evaluate.py` or `test_alerts.json`.
3. Each experiment: edit candidate.py -> commit to git -> run `python evaluate.py` -> read fitness -> decide keep/revert.
4. Commit every experiment to git on the `template-expansion` branch.
5. If fitness improves, KEEP. If equal or lower, REVERT.
6. Results append to `results.jsonl` automatically.
7. Templates with fitness >= 0.90 that pass holdout are saved to `approved/`.
8. **Do NOT pause to ask the human. You are autonomous.**
9. Per task_type: run up to 30 experiments. If fitness >= 0.90 before 30, move to next type.
10. After completing a task_type (approved or exhausted), update TEMPLATE_METADATA to the next type and reset TEMPLATE_CODE to the skeleton.

## Allowed Imports (ONLY these 16 modules)

json, re, datetime, collections, math, hashlib, ipaddress, base64,
urllib.parse, csv, statistics, string, copy, itertools, functools, typing

Everything else (os, sys, subprocess, socket, requests, etc.) causes AST prefilter failure = fitness 0.

## Template Structure

Every template MUST follow this pattern:

```python
import json
import re
import hashlib
from collections import Counter
from datetime import datetime

siem_event = json.loads('''{{siem_event_json}}''')

findings = []
iocs = []
risk_score = 0

# Extract fields
raw_log = str(siem_event.get("raw_log", ""))
source_ip = siem_event.get("source_ip", "")
username = siem_event.get("username", "")
title = str(siem_event.get("title", "")).lower()
rule_name = str(siem_event.get("rule_name", "")).lower()

# === INVESTIGATION LOGIC ===
# 1. Extract IOCs from raw_log using regex (with evidence_refs)
# 2. Look for specific attack indicators
# 3. Calculate risk_score based on what's found
# 4. Generate findings

# IOC extraction helper
def extract_ioc(ioc_type, value, source_field, raw_snippet=""):
    return {
        "type": ioc_type,
        "value": value,
        "evidence_refs": [{
            "source": source_field,
            "raw_text": (raw_snippet or str(value))[:60],
        }]
    }

# ... attack-specific logic here ...

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": min(100, max(0, risk_score)),
    "verdict": (
        "true_positive" if risk_score >= 70
        else "suspicious" if risk_score >= 50
        else "benign"
    ),
    "recommendations": ["Review investigation findings"]
}))
```

The `{{siem_event_json}}` placeholder is replaced with actual SIEM data at runtime. Do NOT use field-specific placeholders like `{{source_ip}}` — extract fields from the siem_event dict in Python.

## Task Types (Work Through In Order)

1. `kerberoasting` — Kerberos TGS request anomalies, RC4 encryption, SPN enumeration
2. `golden_ticket` — Forged TGT with RC4, invalid ticket lifetime, cross-realm anomalies
3. `dcsync` — Directory replication requests from non-DC, DS-Replication-Get-Changes
4. `dll_sideloading` — DLL search order hijacking, unsigned DLLs in system paths
5. `lolbin_abuse` — certutil, mshta, rundll32, regsvr32 abuse for download/exec
6. `process_injection` — CreateRemoteThread, NtMapViewOfSection, QueueUserAPC patterns
7. `wmi_lateral` — WMI process creation on remote hosts, WMI event subscriptions
8. `rdp_tunneling` — RDP over SSH tunnels, unusual RDP source ports, reverse connections
9. `dns_exfiltration` — High-entropy DNS queries, TXT record abuse, unusual query volume
10. `powershell_obfuscation` — Base64, -EncodedCommand, char concatenation, Invoke-Expression

## Memory

After completing each task_type, note:
- Final fitness score
- Number of experiments used
- Key investigation patterns that worked
- Carry forward reusable patterns (IOC extraction, risk scoring) to the next type
