"""
Benchmark Qwen2.5-14B via local llama-server API.
Tests 7 SIEM investigations — measures code gen, IOC extraction, risk scoring.
Works with both base model and DPO-merged GGUF (swap the model file in llama-server).
"""
import json, time, re, subprocess, sys, os
import urllib.request

API_URL = os.environ.get("LLM_URL", "http://localhost:11434/v1/chat/completions")

INVESTIGATIONS = [
    {
        "name": "SSH Brute Force",
        "task_type": "brute_force",
        "siem_event": {
            "title": "SSH Brute Force Attack",
            "source_ip": "10.0.0.99",
            "destination_ip": "10.0.0.5",
            "hostname": "WEB-SERVER-01",
            "username": "admin",
            "rule_name": "SSH_Brute_Force",
            "raw_log": "Failed password for admin from 10.0.0.99 port 54321 ssh2\nFailed password for admin from 10.0.0.99 port 54322 ssh2\nFailed password for root from 10.0.0.99 port 54323 ssh2\nAccepted password for admin from 10.0.0.99 port 54324 ssh2"
        },
        "expected_iocs": ["10.0.0.99", "10.0.0.5", "admin"]
    },
    {
        "name": "Lateral Movement PtH",
        "task_type": "lateral_movement",
        "siem_event": {
            "title": "Pass the Hash Attack",
            "source_ip": "10.0.0.50",
            "destination_ip": "10.0.0.200",
            "hostname": "WS-FINANCE-03",
            "username": "svc_backup",
            "rule_name": "PtH_Detected",
            "raw_log": "EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY TargetIP=10.0.0.200 User=svc_backup NTLM_hash=aad3b435b51404eeaad3b435b51404ee Process=svchost.exe ParentProcess=mimikatz.exe"
        },
        "expected_iocs": ["10.0.0.50", "10.0.0.200", "svc_backup", "aad3b435b51404eeaad3b435b51404ee"]
    },
    {
        "name": "C2 Beaconing",
        "task_type": "c2_communication",
        "siem_event": {
            "title": "C2 Beacon Detected",
            "source_ip": "10.0.0.15",
            "destination_ip": "185.220.101.42",
            "hostname": "WORKSTATION-07",
            "username": "jsmith",
            "rule_name": "C2_Beacon",
            "raw_log": "DNS query: evil-c2.xyz from 10.0.0.15\nHTTP POST http://185.220.101.42/beacon interval=60s size=256b\nUserAgent=Mozilla/5.0 (compatible; bot)"
        },
        "expected_iocs": ["10.0.0.15", "185.220.101.42", "evil-c2.xyz"]
    },
    {
        "name": "Ransomware Encryption",
        "task_type": "ransomware",
        "siem_event": {
            "title": "Ransomware File Encryption",
            "source_ip": "10.0.0.75",
            "destination_ip": "10.0.0.100",
            "hostname": "FILE-SERVER-01",
            "username": "bob.jones",
            "rule_name": "Ransomware_Detected",
            "raw_log": "FileRename: documents.docx -> documents.docx.locked\nFileRename: report.xlsx -> report.xlsx.locked\nProcess=cryptor.exe MD5=d41d8cd98f00b204e9800998ecf8427e\nRegistryWrite: HKLM\\Software\\Ransom\\key=INFECTED"
        },
        "expected_iocs": ["10.0.0.75", "cryptor.exe", "d41d8cd98f00b204e9800998ecf8427e"]
    },
    {
        "name": "Phishing Email",
        "task_type": "phishing",
        "siem_event": {
            "title": "Phishing Email Detected",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "hostname": "MAIL-SERVER",
            "username": "alice@corp.local",
            "rule_name": "Phishing_Detected",
            "raw_log": "From: attacker@evil.com To: alice@corp.local Subject: Urgent Invoice\nURL: http://phish.evil.com/steal-creds\nAttachment: invoice.exe MD5=5d41402abc4b2a76b9719d911017c592"
        },
        "expected_iocs": ["attacker@evil.com", "phish.evil.com", "5d41402abc4b2a76b9719d911017c592"]
    },
    {
        "name": "Data Exfiltration",
        "task_type": "data_exfiltration",
        "siem_event": {
            "title": "Large Data Transfer Detected",
            "source_ip": "10.0.0.30",
            "destination_ip": "203.0.113.99",
            "hostname": "DB-SERVER-01",
            "username": "db_admin",
            "rule_name": "Data_Exfil",
            "raw_log": "Outbound transfer: 10.0.0.30 -> 203.0.113.99 size=4.2GB protocol=HTTPS\nProcess=rclone.exe args=copy /data s3://external-bucket\nUser=db_admin elevated=true"
        },
        "expected_iocs": ["10.0.0.30", "203.0.113.99", "db_admin", "rclone.exe"]
    },
    {
        "name": "Privilege Escalation",
        "task_type": "privilege_escalation",
        "siem_event": {
            "title": "Privilege Escalation Detected",
            "source_ip": "10.0.0.22",
            "destination_ip": "10.0.0.1",
            "hostname": "WORKSTATION-12",
            "username": "temp_user",
            "rule_name": "PrivEsc_Detected",
            "raw_log": "EventID=4672 PrivilegesAssigned=SeDebugPrivilege User=temp_user\nProcess=psexec.exe -s cmd.exe\nEventID=4624 LogonType=2 User=SYSTEM Source=10.0.0.22\nNew service created: malware_svc path=C:\\Windows\\Temp\\evil.exe"
        },
        "expected_iocs": ["10.0.0.22", "temp_user", "psexec.exe", "evil.exe"]
    }
]

SYSTEM_PROMPT = """You are a security analyst writing Python investigation scripts.

RULES — follow exactly:
1. Embed the SIEM alert data as a Python DICTIONARY LITERAL assigned to a variable.
   NEVER use json.loads() to parse the alert data.
2. Assign raw_log = alert['raw_log'] then use regex (re module) to extract IOCs from it.
3. Extract ALL of: IP addresses, hostnames, usernames, file hashes, file paths, domains, emails.
4. Print ONLY valid JSON to stdout using json.dumps() with keys:
   findings (array of {title, details}), iocs (array of {type, value, confidence}),
   risk_score (int 0-100), recommendations (array of strings).
5. Use ONLY stdlib (re, json, collections). No os, sys, subprocess, socket.
6. No input(), no network calls, no file I/O.
7. Keep it SHORT — under 80 lines."""


def call_llm(prompt):
    payload = json.dumps({
        "model": "Qwen2.5-14B-Instruct-Q4_K_M.gguf",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 800,
    }).encode()
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=600)
        data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  LLM error: {e}")
        return None


def extract_code(response):
    if not response:
        return None
    code_match = re.search(r'```python\n(.*?)```', response, re.DOTALL)
    if code_match:
        return code_match.group(1)
    # Try without fence
    if "import re" in response or "import json" in response:
        return response
    return None


def execute_code(code):
    if not code:
        return None
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            # Find the JSON in stdout (might have extra output)
            stdout = result.stdout.strip()
            # Try parsing the whole thing
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                # Try to find JSON object
                match = re.search(r'\{.*\}', stdout, re.DOTALL)
                if match:
                    return json.loads(match.group())
        else:
            if result.stderr:
                print(f"  Exec error: {result.stderr[:100]}")
    except subprocess.TimeoutExpired:
        print(f"  Timeout (30s)")
    except Exception as e:
        print(f"  Exec error: {e}")
    return None


def check_iocs(found_iocs, expected):
    if not found_iocs:
        return 0, len(expected)
    found_values = []
    for ioc in found_iocs:
        if isinstance(ioc, dict):
            v = ioc.get("value", "")
        else:
            v = ioc
        # Handle list/nested values
        if isinstance(v, list):
            found_values.extend(str(x).lower() for x in v)
        else:
            found_values.append(str(v).lower())
    hits = sum(1 for e in expected if any(e.lower() in v for v in found_values))
    return hits, len(expected)


def main():
    print(f"=== HYDRA Benchmark: {API_URL} ===")
    print(f"Model: Qwen2.5-14B-Instruct Q4_K_M (llama-server)")
    print(f"Investigations: {len(INVESTIGATIONS)}\n")

    results = []
    for i, inv in enumerate(INVESTIGATIONS, 1):
        print(f"[{i}/7] {inv['name']}...")
        t0 = time.time()

        prompt = f"""SIEM ALERT (embed as Python dict literal, do NOT use json.loads):
alert = {repr(inv['siem_event'])}

raw_log = alert['raw_log']

Write a Python script that extracts ALL IOCs from raw_log using regex.
Analyze this {inv['task_type']} incident. Output JSON."""

        response = call_llm(prompt)
        code = extract_code(response)
        output = execute_code(code)
        elapsed = time.time() - t0

        if output and isinstance(output, dict):
            iocs = output.get("iocs", [])
            findings = output.get("findings", [])
            risk = output.get("risk_score", 0)
            ioc_hits, ioc_total = check_iocs(iocs, inv["expected_iocs"])
            has_findings = len(findings) > 0

            print(f"  Code: OK | Findings: {len(findings)} | IOCs: {ioc_hits}/{ioc_total} | Risk: {risk} | Time: {elapsed:.1f}s")
            results.append({
                "name": inv["name"],
                "success": True,
                "code_gen": True,
                "has_findings": has_findings,
                "findings_count": len(findings),
                "ioc_hits": ioc_hits,
                "ioc_total": ioc_total,
                "ioc_extracted": len(iocs),
                "risk_score": risk,
                "elapsed": elapsed
            })
        else:
            print(f"  FAILED | Time: {elapsed:.1f}s")
            results.append({
                "name": inv["name"],
                "success": False,
                "code_gen": code is not None,
                "elapsed": elapsed
            })

    # Summary
    successes = [r for r in results if r["success"]]
    code_gen_ok = [r for r in results if r.get("code_gen")]
    with_findings = [r for r in successes if r.get("has_findings")]
    total_ioc_hits = sum(r.get("ioc_hits", 0) for r in successes)
    total_ioc_expected = sum(r.get("ioc_total", 0) for r in successes)
    ioc_pass = sum(1 for r in successes if r.get("ioc_hits", 0) > 0)
    mean_risk = sum(r.get("risk_score", 0) for r in successes) // max(len(successes), 1)
    mean_exec = sum(r["elapsed"] for r in results) / len(results)

    print(f"\n{'='*50}")
    print(f"BENCHMARK RESULTS")
    print(f"{'='*50}")
    print(f"Code gen:     {len(code_gen_ok)}/7 ({100*len(code_gen_ok)//7}%)")
    print(f"Execution:    {len(successes)}/7 ({100*len(successes)//7}%)")
    print(f"Findings:     {len(with_findings)}/7 ({100*len(with_findings)//7}%)")
    print(f"IOC extract:  {ioc_pass}/7 ({100*ioc_pass//7}%)")
    print(f"IOC accuracy: {total_ioc_hits}/{total_ioc_expected} ({100*total_ioc_hits//max(total_ioc_expected,1)}%)")
    print(f"Mean risk:    {mean_risk}")
    print(f"Mean exec:    {mean_exec:.1f}s")
    print(f"\nBaseline:     Code 100% | Findings 86% | IOC 29% | Risk 76")

    out_file = "benchmark_results.json"
    with open(out_file, "w") as f:
        json.dump({"model": "base", "results": results}, f, indent=2)
    print(f"Saved: {out_file}")


if __name__ == "__main__":
    main()
