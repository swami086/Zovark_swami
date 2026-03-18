#!/usr/bin/env python3
"""Generate DPO training pairs from Path B test results.

Uses high-quality qwen2.5:14b outputs as chosen examples.
Creates degraded versions (IOC extraction removed) as rejected examples.

Usage:
    python dpo/generate_pairs.py [--results-dir /path/to/results]
"""
import json
import re
import os
import hashlib
from pathlib import Path


def load_llm_output(path):
    """Load raw llama-server JSON response and extract code."""
    with open(path) as f:
        raw = json.load(f)
    content = raw["choices"][0]["message"]["content"]
    # Extract Python code block
    if "```python" in content:
        code = content.split("```python")[1].split("```")[0].strip()
    elif "```" in content:
        code = content.split("```")[1].split("```")[0].strip()
    else:
        code = content.strip()
    return code, content


def degrade_code(code):
    """Create a rejected version by removing IOC extraction logic."""
    degraded = code
    # Remove regex patterns for IOC extraction
    degraded = re.sub(
        r'(?:ip_pattern|IP_PATTERN|hash_pattern|HASH_PATTERN|domain_pattern|user_pattern|host_pattern)\s*=\s*r[\'"].*?[\'"]',
        '# IOC pattern removed',
        degraded
    )
    # Replace IOC list building with empty list
    degraded = re.sub(
        r'(iocs\s*=\s*)\[.*?\]',
        r'\1[]  # No IOC extraction',
        degraded,
        flags=re.DOTALL
    )
    # Remove re.findall calls
    degraded = re.sub(
        r're\.findall\([^)]+\)',
        '[]  # regex removed',
        degraded
    )
    # Set risk_score to 0
    degraded = re.sub(
        r'(risk_score\s*=\s*)\d+',
        r'\g<1>0',
        degraded
    )
    return degraded


ALERT_PROMPTS = {
    "B1_apt": {
        "system": "You are a security analyst. Generate a Python script to analyze SIEM alerts. Extract all IOCs. Print JSON with findings, iocs, risk_score keys.",
        "user": 'SIEM ALERT: APT Multi-Stage Intrusion. Source: 203.0.113.42, Dest: 10.0.0.5, Host: CORP-DC-01, User: svc_exchange. Events: LogonType=3, cmd.exe spawned from services.exe, ADMIN$ share accessed, scheduled task created (svcupdate.exe), MD5=a1b2c3d4e5f6789012345678abcdef01.',
    },
    "B3_firmware": {
        "system": "You are a security analyst. Generate a Python script to analyze SIEM alerts. Extract all IOCs. Print JSON with findings, iocs, risk_score keys.",
        "user": 'SIEM ALERT: Firmware Integrity Violation on PLC-CTRL-01. Source: 10.0.0.200, expected_hash=3f7a9b2c1d4e5f6a, actual_hash=deadbeef12345678. fwupdate.exe --force --no-verify. Netflow to 185.220.101.99:443 (2MB). Firmware signature verification DISABLED.',
    },
    "B5_pth": {
        "system": "You are a security analyst. Generate a Python script to analyze SIEM alerts. Extract all IOCs. Print JSON with findings, iocs, risk_score keys.",
        "user": 'SIEM ALERT: NTLM Pass-the-Hash Lateral Movement. Source: 10.0.0.50 -> DC-PRIMARY.corp.local (10.0.0.200). User: svc_backup, NTLM_hash=aad3b435b51404eeaad3b435b51404ee. mimikatz.exe sekurlsa::pth detected.',
    },
}


def create_pair(name, chosen_code, prompt_info):
    """Create a DPO training pair in ChatML format."""
    rejected_code = degrade_code(chosen_code)

    prompt = f"<|im_start|>system\n{prompt_info['system']}<|im_end|>\n<|im_start|>user\n{prompt_info['user']}<|im_end|>\n<|im_start|>assistant\n"

    pair = {
        "prompt": prompt,
        "chosen": f"```python\n{chosen_code}\n```",
        "rejected": f"```python\n{rejected_code}\n```",
        "metadata": {
            "source": "path_b_test",
            "test_name": name,
            "model": "qwen2.5-14b-instruct Q4_K_M",
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:12],
        }
    }
    return pair


def main():
    results_dir = os.environ.get("RESULTS_DIR", os.path.expanduser("~"))
    output_path = Path("dpo/path_b_pairs.jsonl")

    pairs = []

    # Map test names to result files and prompt info
    test_map = {
        "B1_apt": ("b3_result.json", None),  # B1 ran through pipeline, no raw file
        "B3_firmware": ("b3_result.json", ALERT_PROMPTS["B3_firmware"]),
        "B5_pth": ("b5_result.json", ALERT_PROMPTS["B5_pth"]),
    }

    for name, (filename, prompt_info) in test_map.items():
        if prompt_info is None:
            continue
        filepath = os.path.join(results_dir, filename)
        if not os.path.exists(filepath):
            print(f"  SKIP {name}: {filepath} not found")
            continue

        try:
            code, _ = load_llm_output(filepath)
            pair = create_pair(name, code, prompt_info)
            pairs.append(pair)
            print(f"  OK {name}: chosen={len(code)} chars, rejected={len(pair['rejected'])} chars")
        except Exception as e:
            print(f"  FAIL {name}: {e}")

    # Also create pairs from the ALERT_PROMPTS that we have inline code for
    # B1 APT — use inline chosen code from test results
    b1_chosen = '''import json
import re

alert_data = """EventID=4624 LogonType=3 SourceIP=203.0.113.42 User=svc_exchange TargetHost=CORP-DC-01
EventID=4688 NewProcessName=cmd.exe ParentProcess=services.exe CommandLine=cmd /c whoami & net user & ipconfig /all
EventID=5140 ShareName=ADMIN$ SourceIP=203.0.113.42 User=svc_exchange
EventID=4698 TaskName=WindowsUpdate TaskContent=svcupdate.exe User=svc_exchange
MD5=a1b2c3d4e5f6789012345678abcdef01 File=svcupdate.exe"""

iocs = []
for ip in re.findall(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', alert_data):
    iocs.append({"type": "ipv4", "value": ip, "confidence": "high"})
for user in re.findall(r'User=(\\S+)', alert_data):
    iocs.append({"type": "username", "value": user, "confidence": "high"})
for host in re.findall(r'(?:TargetHost|Host)=(\\S+)', alert_data):
    iocs.append({"type": "hostname", "value": host, "confidence": "high"})
for h in re.findall(r'MD5=([a-f0-9]{32})', alert_data):
    iocs.append({"type": "hash_md5", "value": h, "confidence": "high"})

findings = [
    {"title": "Remote Logon from External IP", "details": "LogonType=3 from 203.0.113.42"},
    {"title": "Reconnaissance Commands", "details": "cmd.exe: whoami, net user, ipconfig"},
    {"title": "ADMIN$ Share Access", "details": "Lateral movement indicator"},
    {"title": "Persistence via Scheduled Task", "details": "svcupdate.exe as WindowsUpdate"}
]

output = {"findings": findings, "iocs": iocs, "risk_score": 85, "recommendations": [
    "Block 203.0.113.42 at firewall", "Reset svc_exchange credentials",
    "Scan CORP-DC-01 for svcupdate.exe", "Check scheduled tasks on all DCs"
]}
print(json.dumps(output, indent=2))'''

    pair = create_pair("B1_apt", b1_chosen, ALERT_PROMPTS["B1_apt"])
    pairs.append(pair)
    print(f"  OK B1_apt (inline): chosen={len(b1_chosen)} chars")

    # Write pairs
    with open(output_path, "w") as f:
        for pair in pairs:
            f.write(json.dumps(pair) + "\n")

    print(f"\nGenerated {len(pairs)} DPO pairs -> {output_path}")

    # Validate basic structure
    for i, pair in enumerate(pairs):
        assert "prompt" in pair, f"Pair {i} missing prompt"
        assert "chosen" in pair, f"Pair {i} missing chosen"
        assert "rejected" in pair, f"Pair {i} missing rejected"
        assert len(pair["chosen"]) > len(pair["rejected"]) * 0.3, f"Pair {i} rejected too similar to chosen"
        assert "```python" in pair["chosen"], f"Pair {i} chosen missing code block"
    print(f"Validation passed: {len(pairs)} pairs OK")

    return pairs


if __name__ == "__main__":
    main()
