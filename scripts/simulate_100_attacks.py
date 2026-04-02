#!/usr/bin/env python3
"""
Simulate 100 attacks through Zovark API
Generates results and analysis
"""
import json
import random
import time
import sys

# Load existing attack vectors
with open('/app/attack_vectors.json') as f:
    base_vectors = json.load(f)

# Generate 100 attack variations
attacks = []

# First 40: Original vectors (adapted structure)
for v in base_vectors[:40]:
    attacks.append({
        "id": v["id"],
        "name": v["name"],
        "task_type": v.get("task_type", "brute_force"),
        "siem_event": v.get("siem_event", {}),
        "expected_detection": True,
        "min_risk": v.get("expected_risk_min", 50)
    })

# Generate 60 variations with different IPs, usernames, payloads
attack_types = [
    "brute_force",
    "lateral_movement", 
    "privilege_escalation",
    "defense_evasion",
    "persistence",
    "c2",
    "data_exfil",
    "ransomware",
    "credential_access",
    "discovery"
]

# Generate 60 more attacks
for i in range(60):
    attack_type = attack_types[i % len(attack_types)]
    
    # Vary the source IP
    src_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}"
    dst_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}"
    
    # Generate attack payload
    if "brute" in attack_type:
        raw_log = f"Failed login attempts from {src_ip} - 500 attempts in 60 seconds"
        severity = "high"
    elif "lateral" in attack_type:
        raw_log = f"PsExec execution from {src_ip} to {dst_ip} with admin credentials"
        severity = "critical"
    elif "privilege" in attack_type:
        raw_log = f"UAC bypass attempt via fodhelper.exe from {src_ip}"
        severity = "critical"
    elif "defense" in attack_type:
        raw_log = f"AMSI bypass pattern detected in PowerShell from {src_ip}"
        severity = "high"
    elif "persistence" in attack_type:
        raw_log = f"New service created: WindowsUpdateSvc pointing to C:\\temp\\payload.exe"
        severity = "high"
    elif "c2" in attack_type:
        raw_log = f"Regular beacon detected from {src_ip} to 192.168.1.100:4444 interval=60s"
        severity = "critical"
    elif "exfil" in attack_type:
        raw_log = f"Large data transfer: 2GB uploaded to dropbox.com from {src_ip}"
        severity = "high"
    elif "ransomware" in attack_type:
        raw_log = f"vssadmin delete shadows /all /quiet executed on {src_ip}"
        severity = "critical"
    elif "credential" in attack_type:
        raw_log = f"LSASS memory access from {src_ip} using procdump.exe"
        severity = "critical"
    else:
        raw_log = f"Suspicious activity detected from {src_ip}"
        severity = "medium"
    
    attacks.append({
        "id": f"SIM-{i+41:03d}",
        "name": f"Simulated {attack_type.replace('_', ' ').title()}",
        "task_type": attack_type,
        "siem_event": {
            "raw_log": raw_log,
            "source_ip": src_ip,
            "destination_ip": dst_ip if "lateral" in attack_type or "c2" in attack_type else "",
            "username": f"user{random.randint(1, 100)}",
            "severity": severity
        },
        "expected_detection": True,
        "min_risk": random.randint(50, 95)
    })

print(f"Generated {len(attacks)} attacks for simulation")
print(f"- Original vectors: 40")
print(f"- Generated variations: 60")
print()

# Save attack list
with open('/app/simulation_100_attacks.json', 'w') as f:
    json.dump(attacks, f, indent=2)

print("Attack list saved to /app/simulation_100_attacks.json")
