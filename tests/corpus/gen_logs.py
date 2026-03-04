import os
import random
from datetime import datetime, timedelta

def generate_brute_force_easy():
    filepath = "/app/tests/corpus/brute_force/easy.log"
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    start_time = datetime(2026, 3, 1, 10, 0, 0)
    lines = []
    
    # Lines 1-50: "Failed password" from IP 203.0.113.50 targeting user "admin"
    attacker_ip = "203.0.113.50"
    for i in range(50):
        t = start_time + timedelta(seconds=i)
        lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from {attacker_ip} port 22\n')
    
    # Line 51: "Accepted password" for admin from 203.0.113.50
    t = start_time + timedelta(seconds=50)
    lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for admin from {attacker_ip} port 22\n')
    
    # Lines 52-500: Normal "Accepted password" from various legitimate IPs
    legit_users = ["user1", "user2", "backup", "deploy", "jenkins"]
    for i in range(51, 500):
        t = start_time + timedelta(minutes=i)
        user = random.choice(legit_users)
        ip = f"10.0.0.{random.randint(1, 254)}"
        lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for {user} from {ip} port 22\n')
        
    with open(filepath, "w") as f:
        f.writelines(lines)

def generate_brute_force_hard():
    filepath = "/app/tests/corpus/brute_force/hard.log"
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    start_time = datetime(2026, 3, 1, 10, 0, 0)
    lines = []
    
    # 2000 lines total. 15 attacks starting around line 200 randomly, up to 1800
    legit_users = ["user1", "user2", "backup", "deploy", "jenkins"]
    attacker_ip = "203.0.113.99"
    
    attack_indices = sorted(random.sample(range(200, 1800), 15))
    attack_indices.append(1900) # success line
    
    attack_count = 0
    for i in range(2000):
        t = start_time + timedelta(minutes=i)
        if i in attack_indices:
            if i == 1900:
                lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for admin from {attacker_ip} port 22\n')
            else:
                lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from {attacker_ip} port 22\n')
        else:
            user = random.choice(legit_users)
            ip = f"10.0.0.{random.randint(1, 254)}"
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for {user} from {ip} port 22\n')
            
    with open(filepath, "w") as f:
        f.writelines(lines)

def generate_brute_force_multi():
    filepath = "/app/tests/corpus/brute_force/multi_attack.log"
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    start_time = datetime(2026, 3, 1, 10, 0, 0)
    lines = []
    legit_users = ["user1", "user2", "backup", "deploy", "jenkins"]
    
    for i in range(1000):
        t = start_time + timedelta(seconds=i*10)
        
        # Lines 1-30: Brute force from 198.51.100.10 (30 fail, then 1 accept)
        if i < 30:
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from 198.51.100.10 port 22\n')
        elif i == 30:
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for admin from 198.51.100.10 port 22\n')
            
        # Lines 100-111: Credential stuffing from 198.51.100.20 (12 fail for 12 diff users)
        elif 100 <= i < 112:
            u_num = i - 100
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user fakeuser{u_num} from 198.51.100.20 port 22\n')
            
        # Lines 200-203: Password spray from 4 IPs trying admin
        elif 200 <= i < 204:
            spray_ip = f"45.33.22.{i}"
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Failed password for invalid user admin from {spray_ip} port 22\n')
            
        # Rest: legit
        else:
            user = random.choice(legit_users)
            ip = f"10.0.0.{random.randint(1, 254)}"
            lines.append(f'{t.strftime("%Y-%m-%dT%H:%M:%SZ")} host sshd[{random.randint(100, 999)}]: Accepted password for {user} from {ip} port 22\n')
            
    with open(filepath, "w") as f:
        f.writelines(lines)

if __name__ == "__main__":
    generate_brute_force_easy()
    generate_brute_force_hard()
    generate_brute_force_multi()
    print("Brute force logs generated successfully.")


