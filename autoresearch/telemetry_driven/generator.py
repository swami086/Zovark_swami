"""Test generator — creates targeted alerts from identified weaknesses."""

import random
import hashlib
from typing import List, Dict
from analyzer import Weakness

ALERT_TEMPLATES = {
    "brute_force": [
        {"severity": "high", "source_ip": "185.220.101.{r}", "username": "root",
         "rule_name": "SSH Brute Force",
         "raw_log": "{c} failed login attempts for root from 185.220.101.{r} in 60 seconds via sshd Failed Failed Failed Failed Failed"},
        {"severity": "critical", "source_ip": "45.33.32.{r}", "username": "admin",
         "rule_name": "RDP Brute Force",
         "raw_log": "EventID=4625 {c} failed RDP logons for admin from 45.33.32.{r} AccountLockout"},
    ],
    "phishing": [
        {"severity": "high", "source_ip": "203.0.113.{r}",
         "rule_name": "Phishing URL",
         "raw_log": "URGENT verify your account immediately or suspended. Click here: https://login-verify-portal.com/auth/login.php password credential From: alert@amaz0n-security.com"},
    ],
    "ransomware": [
        {"severity": "critical", "source_ip": "10.0.50.{r}", "hostname": "SRV-{r}",
         "rule_name": "Ransomware",
         "raw_log": "vssadmin delete shadows detected. wmic shadowcopy delete. Files .locked extension. README_DECRYPT.txt bitcoin payment ransom demanded."},
    ],
    "kerberoasting": [
        {"severity": "high", "source_ip": "10.0.20.{r}",
         "rule_name": "Kerberoasting",
         "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433 TargetUserName=attacker ClientAddress=10.0.20.{r}"},
    ],
    "dns_exfiltration": [
        {"severity": "high", "source_ip": "10.0.30.{r}",
         "domain": "aGVsbG8gZXhmaWx0cmF0aW9u.evil-dns.com",
         "rule_name": "DNS Exfiltration",
         "raw_log": "DNS TXT query: aGVsbG8gZXhmaWx0cmF0aW9u.evil-dns.com type=TXT queries=200 dns exfiltration high entropy tunnel nslookup 10.0.30.{r}"},
    ],
    "c2_communication": [
        {"severity": "high", "source_ip": "10.0.10.{r}",
         "rule_name": "C2 Beacon",
         "raw_log": "beacon interval=60s stddev=1.2 connections=150 to xk7q9m2p.evil-c2.net:443 c2 beacon callback implant"},
    ],
    "data_exfiltration": [
        {"severity": "high", "source_ip": "10.0.40.{r}",
         "rule_name": "Data Exfiltration",
         "raw_log": "Transfer 2.5 GB to 203.0.113.99 external after.hours archive.rar compressed encrypted off-hours upload to dropbox"},
    ],
    "lolbin_abuse": [
        {"severity": "high", "source_ip": "10.0.60.{r}", "hostname": "WS-{r}",
         "rule_name": "LOLBin Abuse",
         "raw_log": "mshta.exe vbscript:Execute(CreateObject(Wscript.Shell).Run(malicious)) bitsadmin transfer download http://bad.host/stage2.bin"},
    ],
    "lateral_movement": [
        {"severity": "high", "source_ip": "10.0.20.{r}", "destination_ip": "10.0.20.{r2}",
         "rule_name": "PsExec Lateral",
         "raw_log": "psexec.exe \\\\10.0.20.{r2} -u admin cmd.exe pass-the-hash ntlm admin$ lateral remote"},
    ],
    "golden_ticket": [
        {"severity": "critical", "source_ip": "10.0.20.{r}",
         "rule_name": "Golden Ticket",
         "raw_log": "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt Lifetime=8760h TicketOptions=0x50800000 ClientAddress=10.0.20.{r}"},
    ],
    "powershell_obfuscation": [
        {"severity": "high", "source_ip": "10.0.1.{r}", "hostname": "WS-{r}",
         "rule_name": "Obfuscated PowerShell",
         "raw_log": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA -nop -w hidden DownloadString IEX Invoke-Expression bypass amsi ScriptBlock"},
    ],
}

BENIGN_TEMPLATES = {
    "password_change": {"severity": "info", "raw_log": "User jdoe changed password successfully via self-service portal"},
    "windows_update": {"severity": "info", "raw_log": "Windows Update KB5034441 installed successfully on WORKSTATION-01"},
    "health_check": {"severity": "info", "raw_log": "System health check passed. CPU 45 percent Memory 62 percent. All services normal."},
    "scheduled_backup": {"severity": "info", "raw_log": "Nightly backup completed successfully. 150 GB backed up."},
    "user_login": {"severity": "info", "raw_log": "User asmith logged in via RDP from 10.0.1.150 at 09:00 UTC"},
}


class TestGenerator:
    def __init__(self, weaknesses: List[Weakness]):
        self.weaknesses = weaknesses

    def generate(self, max_tests=30) -> List[Dict]:
        tests = []
        seen_types = set()
        for w in self.weaknesses:
            if len(tests) >= max_tests - len(BENIGN_TEMPLATES):
                break
            generated = self._for_weakness(w)
            for t in generated:
                if t["task_type"] not in seen_types or len(tests) < 5:
                    tests.append(t)
                    seen_types.add(t["task_type"])
        tests.extend(self._benign_baseline())
        return tests[:max_tests]

    def _for_weakness(self, w: Weakness) -> List[Dict]:
        tt = w.task_type
        if tt == "*" or tt.startswith("path:"):
            return self._diverse(2)
        templates = ALERT_TEMPLATES.get(tt, [])
        if not templates:
            return [self._generic(tt, w)]
        return [self._fill(tt, t, w) for t in templates[:2]]

    def _fill(self, task_type, template, weakness):
        r = random.randint(1, 254)
        r2 = random.randint(1, 254)
        c = random.choice([100, 250, 500])
        siem = {}
        for k, v in template.items():
            if isinstance(v, str):
                v = v.replace("{r}", str(r)).replace("{r2}", str(r2)).replace("{c}", str(c))
            siem[k] = v
        siem.setdefault("title", siem.get("rule_name", task_type))
        return {
            "name": f"{task_type}_{hashlib.md5(str(siem).encode()).hexdigest()[:6]}",
            "task_type": task_type,
            "input": {
                "prompt": f"AutoResearch test: {weakness.description[:80]}",
                "severity": siem.pop("severity", "high"),
                "siem_event": siem
            },
            "expect": "attack", "min_risk": 65,
            "weakness_ref": weakness.description[:100],
        }

    def _benign_baseline(self):
        alerts = []
        for tt, tpl in BENIGN_TEMPLATES.items():
            alerts.append({
                "name": f"benign_{tt}",
                "task_type": tt,
                "input": {
                    "prompt": f"Benign baseline: {tt}",
                    "severity": tpl["severity"],
                    "siem_event": {
                        "title": tt.replace("_", " ").title(),
                        "rule_name": tt,
                        "raw_log": tpl["raw_log"],
                        "hostname": f"BASELINE-{random.randint(1,99):02d}",
                    }
                },
                "expect": "benign", "max_risk": 25,
                "weakness_ref": "baseline regression",
            })
        return alerts

    def _diverse(self, count):
        types = list(ALERT_TEMPLATES.keys())
        random.shuffle(types)
        out = []
        dummy = Weakness("diverse", "medium", "", "diverse sample", "", 0, 0, 0)
        for t in types[:count]:
            tpl = random.choice(ALERT_TEMPLATES[t])
            out.append(self._fill(t, tpl, dummy))
        return out

    def _generic(self, task_type, weakness):
        r = random.randint(1, 254)
        return {
            "name": f"generic_{task_type}",
            "task_type": task_type,
            "input": {
                "prompt": f"Generic test: {task_type}",
                "severity": "high",
                "siem_event": {
                    "title": f"Test: {task_type}",
                    "source_ip": f"10.0.1.{r}",
                    "rule_name": f"AutoTest-{task_type}",
                    "raw_log": f"Auto-generated for {task_type} from 10.0.1.{r} suspicious activity",
                }
            },
            "expect": "attack", "min_risk": 50,
            "weakness_ref": weakness.description[:100],
        }
