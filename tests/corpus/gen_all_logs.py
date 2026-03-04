import os
import random
import json
from datetime import datetime, timedelta

BASE_DIR = "/app/tests/corpus"

def ensure_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

# --- BRUTE FORCE ---
def gen_brute_force():
    folder = os.path.join(BASE_DIR, "brute_force")
    os.makedirs(folder, exist_ok=True)
    
    # Easy
    lines = []
    start = datetime(2026, 3, 1, 10, 0, 0)
    for i in range(50):
        t = start + timedelta(seconds=i)
        lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from 203.0.113.50 port 22\n')
    t = start + timedelta(seconds=50)
    lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for admin from 203.0.113.50 port 22\n')
    for i in range(51, 500):
        t = start + timedelta(minutes=i)
        user = random.choice(["user1", "user2", "backup"])
        ip = f"10.0.0.{random.randint(1, 254)}"
        lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for {user} from {ip} port 22\n')
    with open(os.path.join(folder, "easy.log"), "w") as f: f.writelines(lines)
        
    # Hard
    lines = []
    attacks = sorted(random.sample(range(200, 1800), 15))
    attacks.append(1900) # success
    for i in range(2000):
        t = start + timedelta(minutes=i)
        if i in attacks:
            if i == 1900:
                lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for admin from 203.0.113.99 port 22\n')
            else:
                lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from 203.0.113.99 port 22\n')
        else:
            user = random.choice(["user1", "user2", "backup"])
            ip = f"10.0.0.{random.randint(1, 254)}"
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for {user} from {ip} port 22\n')
    with open(os.path.join(folder, "hard.log"), "w") as f: f.writelines(lines)
        
    # Multi
    lines = []
    for i in range(1000):
        t = start + timedelta(seconds=i*10)
        if i < 30:
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from 198.51.100.10 port 22\n')
        elif i == 30:
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for admin from 198.51.100.10 port 22\n')
        elif 100 <= i < 112:
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user fakeuser{i-100} from 198.51.100.20 port 22\n')
        elif 200 <= i < 204:
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from 45.33.22.{i} port 22\n')
        else:
            user = random.choice(["user1", "user2", "backup"])
            ip = f"10.0.0.{random.randint(1, 254)}"
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for {user} from {ip} port 22\n')
    with open(os.path.join(folder, "multi_attack.log"), "w") as f: f.writelines(lines)

# --- RANSOMWARE ---
def gen_ransomware():
    folder = os.path.join(BASE_DIR, "ransomware")
    os.makedirs(folder, exist_ok=True)
    start = datetime(2026, 3, 1, 10, 0, 0)
    
    def sysmon_evt(evt_id, t, rule="FileCreate", img="explorer.exe", target="C:\\Users\\admin\\file.docx"):
        return f'<Event><System><EventID>{evt_id}</EventID><TimeCreated SystemTime="{t.strftime("%Y-%m-%dT%H:%M:%S.000000Z")}"/></System><EventData><Data Name="RuleName">{rule}</Data><Data Name="Image">{img}</Data><Data Name="TargetFilename">{target}</Data></EventData></Event>\n'

    # Easy
    lines = []
    for i in range(100):
        t = start + timedelta(seconds=i//10)
        lines.append(sysmon_evt(11, t, img="C:\\temp\\malware.exe", target=f"C:\\Users\\admin\\doc{i}.docx.encrypted"))
    lines.append(sysmon_evt(1, start+timedelta(seconds=11), img="vssadmin.exe", target="delete shadows /all /quiet"))
    for i in range(399):
        t = start + timedelta(minutes=1+i)
        lines.append(sysmon_evt(11, t, target=f"C:\\Users\\admin\\work{i}.docx"))
    with open(os.path.join(folder, "easy.log"), "w") as f: f.writelines(lines)
        
    # Hard
    lines = []
    attack_indices = sorted(random.sample(range(2000), 50))
    smb_indices = sorted(random.sample(range(2000), 5))
    for i in range(2000):
        t = start + timedelta(seconds=i*30)
        if i in attack_indices:
            lines.append(sysmon_evt(11, t, img="svchost.exe", target=f"C:\\Users\\finance\\doc{i}.xlsx.encrypted"))
        elif i in smb_indices:
            lines.append(sysmon_evt(3, t, rule="NetworkConnect", img="svchost.exe", target=f"10.0.0.{random.randint(1,254)}:445"))
        else:
            lines.append(sysmon_evt(11, t, target=f"C:\\Users\\finance\\work{i}.xlsx"))
    with open(os.path.join(folder, "hard.log"), "w") as f: f.writelines(lines)
        
    # Multi
    lines = []
    for i in range(1000):
        t = start + timedelta(seconds=i)
        if i < 80:
            lines.append(sysmon_evt(11, t, img="malware.exe", target=f"C:\\share\\doc{i}.pdf.encrypted"))
        elif 100 <= i < 120:
            lines.append(sysmon_evt(3, t, rule="NetworkConnect", img="powershell.exe", target="203.0.113.100:443"))
        elif 200 <= i < 210:
            lines.append(sysmon_evt(3, t, rule="NetworkConnect", img="cmd.exe", target=f"10.0.0.{i}:445"))
        else:
            lines.append(sysmon_evt(11, t, target=f"C:\\share\\normal{i}.pdf"))
    with open(os.path.join(folder, "multi_attack.log"), "w") as f: f.writelines(lines)

# --- LATERAL MOVEMENT ---
def gen_lateral():
    folder = os.path.join(BASE_DIR, "lateral_movement")
    os.makedirs(folder, exist_ok=True)
    start = datetime(2026, 3, 1, 10, 0, 0)
    
    def evt(eid, t, user="user1", data="normal"):
        return f'<Event><System><EventID>{eid}</EventID><TimeCreated SystemTime="{t.strftime("%Y-%m-%dT%H:%M:%S.000000Z")}"/></System><EventData><Data Name="SubjectUserName">{user}</Data><Data Name="LogonType">3</Data><Data>{data}</Data></EventData></Event>\n'

    # Easy
    lines = []
    for i in range(500):
        t = start + timedelta(minutes=i)
        if i < 5:
            lines.append(evt(4624, t, user="admin", data="Logon from WORKSTATION-1 to SERVER-1"))
        elif 5 <= i < 8:
            lines.append(evt(4688, t, user="admin", data="C:\\Windows\\System32\\PSEXESVC.exe"))
        elif 8 <= i < 10:
            lines.append(evt(4656, t, user="admin", data="Access requested to lsass.exe"))
        else:
            lines.append(evt(4624, t, user="user1", data="Normal interactive logon"))
    with open(os.path.join(folder, "easy.log"), "w") as f: f.writelines(lines)

    # Hard
    lines = []
    wmi_indices = sorted(random.sample(range(2000), 8))
    svc_indices = sorted(random.sample(range(2000), 3))
    for i in range(2000):
        t = start + timedelta(seconds=i*2)
        if i in wmi_indices:
            lines.append(evt(4688, t, user="SYSTEM", data="WmiPrvSE.exe spawned cmd.exe"))
        elif i in svc_indices:
            lines.append(evt(4624, t, user="svc_backup", data="Logon Type 3 to unusual server"))
        else:
            lines.append(evt(4624, t, user="user2", data="Network logon"))
    with open(os.path.join(folder, "hard.log"), "w") as f: f.writelines(lines)

    # Multi
    lines = []
    for i in range(1000):
        t = start + timedelta(seconds=i)
        if i < 20:
            lines.append(evt(4688, t, user="admin", data="PSEXESVC.exe"))
        elif 50 <= i < 70:
            lines.append(evt(4688, t, user="SYSTEM", data="WmiPrvSE.exe spawned cmd.exe"))
        elif 100 <= i < 130:
            lines.append(evt(4688, t, user="admin", data="wsmprovhost.exe")) # powershell remoting
        else:
            lines.append(evt(4624, t, user="user3", data="Normal logon"))
    with open(os.path.join(folder, "multi_attack.log"), "w") as f: f.writelines(lines)

# --- C2 ---
def gen_c2():
    folder = os.path.join(BASE_DIR, "c2")
    os.makedirs(folder, exist_ok=True)
    start = datetime(2026, 3, 1, 10, 0, 0)
    
    def ts(t): return f"{t.timestamp():.6f}"

    # Easy
    lines = []
    for i in range(500):
        t = start + timedelta(minutes=i)
        if i < 60:
            lines.append(f"{ts(start + timedelta(seconds=i*60))}\tUID\t10.0.0.5\t12345\t185.220.101.50\t80\ttcp\thttp\n")
        else:
            lines.append(f"{ts(t)}\tUID\t10.0.0.5\t12345\t8.8.8.8\t443\ttcp\tssl\n")
    with open(os.path.join(folder, "easy.log"), "w") as f: f.writelines(lines)

    # Hard
    lines = []
    c2_t = start
    attack_count = 0
    dns_count = 0
    for i in range(2000):
        t = start + timedelta(seconds=i*5)
        if attack_count < 40 and random.random() < 0.05:
            c2_t += timedelta(seconds=random.randint(45, 90))
            lines.append(f"{ts(c2_t)}\tUID\t10.0.0.5\t12345\t185.220.101.99\t443\ttcp\tssl\n")
            attack_count += 1
        elif dns_count < 30 and random.random() < 0.05:
            entropy = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
            lines.append(f"{ts(t)}\tUID\t10.0.0.5\t12345\t8.8.8.8\t53\tudp\tdns\t{entropy}.suspicious.example.com\n")
            dns_count += 1
        else:
            lines.append(f"{ts(t)}\tUID\t10.0.0.5\t12345\t1.1.1.1\t443\ttcp\tssl\n")
    with open(os.path.join(folder, "hard.log"), "w") as f: f.writelines(lines)

    # Multi
    lines = []
    for i in range(1000):
        t = start + timedelta(seconds=i)
        if i < 50:
            lines.append(f"{ts(start + timedelta(seconds=i*60))}\tUID\t10.0.0.5\t12345\t185.220.101.100\t80\ttcp\thttp\n")
        elif 100 <= i < 130:
            lines.append(f"{ts(t)}\tUID\t10.0.0.5\t12345\t8.8.8.8\t53\tudp\tdns\tdata{i}.tunnel.example.com\n")
        elif 200 <= i < 220:
            lines.append(f"{ts(t)}\tUID\t10.0.0.5\t12345\t185.220.101.101\t4444\ttcp\t-\n")
        else:
            lines.append(f"{ts(t)}\tUID\t10.0.0.5\t12345\t1.1.1.1\t443\ttcp\tssl\n")
    with open(os.path.join(folder, "multi_attack.log"), "w") as f: f.writelines(lines)

# --- PHISHING ---
def gen_phishing():
    folder = os.path.join(BASE_DIR, "phishing")
    os.makedirs(folder, exist_ok=True)
    start = datetime(2026, 3, 1, 10, 0, 0)
    
    # Easy
    lines = []
    for i in range(500):
        if i < 3:
            lines.append(f"From: support@microsoft.com\nReply-To: support@micros0ft.com\nSubject: Invoice\nAuthentication-Results: spf=pass\n\n")
        elif 3 <= i < 6:
            lines.append(f"From: admin@company.com\nSubject: Urgent\nAuthentication-Results: spf=fail\n\n")
        else:
            lines.append(f"From: user{i}@company.com\nSubject: Hello\nAuthentication-Results: spf=pass\n\n")
    with open(os.path.join(folder, "easy.log"), "w") as f: f.writelines(lines)

    # Hard
    lines = []
    for i in range(2000):
        if i < 2:
            lines.append(f"From: notifications@microsoftt.com\nSubject: Alert\nAuthentication-Results: spf=pass\n\n")
        elif i == 2:
            lines.append(f"From: marketing@legit.com\nSubject: Newsletter\nAuthentication-Results: spf=pass\nBody: Hey, click http://evil.com/payload\n\n")
        else:
            lines.append(f"From: user{i}@company.com\nSubject: Hello\nAuthentication-Results: spf=pass\nBody: Hello world\n\n")
    with open(os.path.join(folder, "hard.log"), "w") as f: f.writelines(lines)

    # Multi
    lines = []
    for i in range(1000):
        if i < 5:
            lines.append(f"From: ceo@c0mpany.com\nSubject: Wire Transfer\nAuthentication-Results: spf=fail\n\n")
        elif 5 <= i < 10:
            lines.append(f"From: vendor@partner.com\nSubject: Invoice attached\nAuthentication-Results: spf=pass\nAttachment: invoice.docm\n\n")
        else:
            lines.append(f"From: user{i}@company.com\nSubject: Hello\nAuthentication-Results: spf=pass\n\n")
    with open(os.path.join(folder, "multi_attack.log"), "w") as f: f.writelines(lines)

def update_expected():
    import glob
    
    updates = {
        "easy.expected.json": {"risk_score_range": [30, 100], "finding_count_range": [1, 5]},
        "hard.expected.json": {"risk_score_range": [20, 100], "finding_count_range": [1, 5]},
        "multi_attack.expected.json": {"risk_score_range": [40, 100], "finding_count_range": [2, 10]},
        "clean.expected.json": {"risk_score_range": [0, 15], "finding_count_range": [0, 1]}
    }
    
    for skill in ["brute_force", "ransomware", "lateral_movement", "c2", "phishing"]:
        for ftype, data in updates.items():
            path = os.path.join(BASE_DIR, skill, ftype)
            if os.path.exists(path):
                with open(path, "r") as f:
                    jdata = json.load(f)
                
                jdata["risk_score_range"] = data["risk_score_range"]
                jdata["finding_count_range"] = data["finding_count_range"]
                
                with open(path, "w") as f:
                    json.dump(jdata, f, indent=4)

if __name__ == "__main__":
    gen_brute_force()
    gen_ransomware()
    gen_lateral()
    gen_c2()
    gen_phishing()
    update_expected()
    print("Logs generated and expected configs updated!")
