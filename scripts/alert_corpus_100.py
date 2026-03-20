"""Generate 100 realistic SIEM alerts for template-path stress testing."""
import json, random, hashlib

random.seed(42)

USERS = ["admin", "jsmith", "mwilson", "rthompson", "db_admin", "svc_backup",
         "alice", "bob.jones", "temp_user", "scada_svc"]
HOSTS = [f"WS-{i:03d}" for i in range(1, 51)] + [f"SRV-{i:03d}" for i in range(1, 51)]
DOMAINS = ["evil-c2.xyz", "malware.co", "data-exfil.net", "phish.evil.com",
           "bad-dns.org", "c2-beacon.io", "steal-creds.com", "update.evil.net"]

def rip(): return f"{random.randint(10,203)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
def md5(): return hashlib.md5(str(random.random()).encode()).hexdigest()
def port(): return random.randint(1024, 65535)

GENERATORS = {
    "brute_force": lambda i: {
        "title": f"SSH Brute Force #{i}", "source_ip": rip(), "destination_ip": f"10.0.0.{random.randint(1,50)}",
        "hostname": random.choice(HOSTS), "username": random.choice(USERS[:3]), "rule_name": "SSH_Brute_Force",
        "raw_log": f"sshd[{random.randint(1000,9999)}]: Failed password for {random.choice(USERS[:3])} from {rip()} port {port()} ssh2\n" * 3 +
                   f"sshd[{random.randint(1000,9999)}]: Accepted password for admin from {rip()} port {port()} ssh2"
    },
    "lateral_movement": lambda i: {
        "title": f"Lateral Movement #{i}", "source_ip": f"10.0.0.{random.randint(10,100)}",
        "destination_ip": f"10.0.0.{random.randint(200,250)}", "hostname": random.choice(HOSTS),
        "username": random.choice(USERS), "rule_name": "PtH_Detected",
        "raw_log": f"EventID=4624 LogonType=9 SourceIP=10.0.0.{random.randint(10,100)} TargetHost={random.choice(HOSTS)} TargetIP=10.0.0.{random.randint(200,250)} User={random.choice(USERS)} NTLM_hash={md5()} Process=svchost.exe ParentProcess=mimikatz.exe"
    },
    "c2_communication_hunt": lambda i: {
        "title": f"C2 Beacon #{i}", "source_ip": f"10.0.0.{random.randint(10,200)}",
        "destination_ip": rip(), "hostname": random.choice(HOSTS),
        "username": random.choice(USERS), "rule_name": "C2_Beacon",
        "raw_log": f"DNS query: {random.choice(DOMAINS)} from 10.0.0.{random.randint(10,200)}\nHTTP POST http://{rip()}/beacon interval={random.choice([30,60,120])}s size={random.randint(128,1024)}b\nUserAgent=Mozilla/5.0 (compatible; bot)"
    },
    "privilege_escalation": lambda i: {
        "title": f"PrivEsc #{i}", "source_ip": f"10.0.0.{random.randint(10,100)}",
        "destination_ip": "10.0.0.1", "hostname": random.choice(HOSTS),
        "username": random.choice(USERS), "rule_name": "PrivEsc_Detected",
        "raw_log": f"EventID=4672 PrivilegesAssigned=SeDebugPrivilege User={random.choice(USERS)}\nProcess=psexec.exe -s cmd.exe\nEventID=4624 LogonType=2 User=SYSTEM Source=10.0.0.{random.randint(10,100)}\nNew service created: svc_{random.randint(100,999)} path=C:/Windows/Temp/{md5()[:8]}.exe"
    },
    "data_exfiltration": lambda i: {
        "title": f"Data Exfil #{i}", "source_ip": f"10.0.0.{random.randint(10,100)}",
        "destination_ip": rip(), "hostname": random.choice(HOSTS),
        "username": random.choice(USERS), "rule_name": "Data_Exfil",
        "raw_log": f"Outbound transfer: 10.0.0.{random.randint(10,100)} -> {rip()} size={random.uniform(0.5,10.0):.1f}GB protocol=HTTPS\nProcess=rclone.exe args=copy /data s3://ext-bucket-{random.randint(1,99)}\nUser={random.choice(USERS)} elevated=true"
    },
    "phishing": lambda i: {
        "title": f"Phishing #{i}", "source_ip": f"192.168.1.{random.randint(10,200)}",
        "destination_ip": "192.168.1.1", "hostname": "MAIL-SERVER",
        "username": f"{random.choice(USERS)}@corp.local", "rule_name": "Phishing_Detected",
        "raw_log": f"From: attacker@{random.choice(DOMAINS)} To: {random.choice(USERS)}@corp.local Subject: {random.choice(['Urgent Invoice','Password Reset','Account Suspended'])}\nURL: http://{random.choice(DOMAINS)}/steal-creds\nAttachment: {random.choice(['invoice','report','update'])}.exe MD5={md5()}"
    },
    "ransomware": lambda i: {
        "title": f"Ransomware #{i}", "source_ip": f"10.0.0.{random.randint(50,150)}",
        "destination_ip": f"10.0.0.{random.randint(100,200)}", "hostname": random.choice(HOSTS),
        "username": random.choice(USERS), "rule_name": "Ransomware_Detected",
        "raw_log": f"FileRename: report_{random.randint(1,999)}.docx -> report_{random.randint(1,999)}.docx.locked\nFileRename: data_{random.randint(1,999)}.xlsx -> data_{random.randint(1,999)}.xlsx.locked\nProcess=cryptor.exe MD5={md5()}\nRegistryWrite: HKLM/Software/Ransom/key=INFECTED"
    },
    "insider_threat": lambda i: {
        "title": f"Insider Threat #{i}", "source_ip": f"10.0.0.{random.randint(10,100)}",
        "destination_ip": f"10.0.0.{random.randint(200,250)}", "hostname": random.choice(HOSTS),
        "username": random.choice(USERS), "rule_name": "Insider_Threat",
        "raw_log": f"EventID=4624 LogonType=2 User={random.choice(USERS)} SourceIP=10.0.0.{random.randint(10,100)} Time=23:45:12\nEventID=4663 ObjectName=C:/Finance/Payroll/ AccessCount={random.randint(100,2000)}\nUSB device connected: VendorID=0781 ProductID=5583"
    },
    "supply_chain": lambda i: {
        "title": f"Supply Chain #{i}", "source_ip": f"10.0.0.{random.randint(10,100)}",
        "destination_ip": rip(), "hostname": random.choice(HOSTS),
        "username": "SYSTEM", "rule_name": "Supply_Chain_Compromise",
        "raw_log": f"Process: SolarWinds.BusinessLayerHost.exe Child: rundll32.exe DLL: C:/Windows/SysWOW64/{md5()[:12]}.dll\nOutbound: {rip()}:443 SNI={random.choice(DOMAINS)}\nCert: CN=*.{random.choice(DOMAINS)} Serial={md5()[:16]}"
    },
    "network_beaconing": lambda i: {
        "title": f"DNS Beacon #{i}", "source_ip": f"10.0.0.{random.randint(10,200)}",
        "destination_ip": rip(), "hostname": random.choice(HOSTS),
        "username": random.choice(USERS), "rule_name": "DNS_Beacon",
        "raw_log": "\n".join(
            f"DNS query: {md5()[:16]}.{random.choice(DOMAINS)} from 10.0.0.{random.randint(10,200)}"
            for _ in range(5)
        )
    },
}

# Map generator keys to exact DB threat_types (for template path matching)
TASK_TYPE_MAP = {
    "brute_force": "brute_force_investigation",
    "lateral_movement": "lateral_movement_detection",
    "c2_communication_hunt": "c2_communication_hunt",
    "privilege_escalation": "privilege_escalation_hunt",
    "data_exfiltration": "data_exfiltration_detection",
    "phishing": "phishing_investigation",
    "ransomware": "ransomware_triage",
    "insider_threat": "insider_threat_detection",
    "supply_chain": "supply_chain_compromise",
    "network_beaconing": "c2_communication",
}

alerts = []
for gen_key, gen in GENERATORS.items():
    task_type = TASK_TYPE_MAP[gen_key]  # Use exact DB threat_type
    for i in range(10):
        siem = gen(i + 1)
        alerts.append({
            "task_type": task_type,
            "prompt": f"Investigate {siem['title']}",
            "severity": random.choice(["high", "critical"]),
            "siem_event": siem,
        })

random.shuffle(alerts)

with open("scripts/alert_corpus_100.json", "w") as f:
    json.dump(alerts, f, indent=2)

from collections import Counter
print(f"Generated {len(alerts)} alerts")
for t, c in sorted(Counter(a["task_type"] for a in alerts).items()):
    print(f"  {t}: {c}")
