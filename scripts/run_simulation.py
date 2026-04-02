#!/usr/bin/env python3
"""
Run 100 attack simulation through Zovark detection tools
"""
import json
import sys
import time
sys.path.insert(0, '/app')

# Import worker tools directly for simulation
from tools.detection import (
    detect_kerberoasting, detect_golden_ticket, detect_ransomware,
    detect_phishing, detect_c2, detect_data_exfil, detect_lolbin_abuse,
    detect_lateral_movement, detect_com_hijacking, detect_encoded_service,
    detect_token_impersonation, detect_appcert_dlls
)

# Tool catalog mapping - map task_type to detection function
TOOL_MAP = {
    'brute_force': None,  # Uses scoring
    'lateral_movement': detect_lateral_movement,
    'privilege_escalation': detect_com_hijacking,
    'defense_evasion': detect_encoded_service,
    'persistence': detect_appcert_dlls,
    'c2': detect_c2,
    'data_exfil': detect_data_exfil,
    'ransomware': detect_ransomware,
    'credential_access': detect_token_impersonation,
    'discovery': detect_lolbin_abuse,
    'phishing': detect_phishing,
    'kerberoasting': detect_kerberoasting,
}

print("=" * 60)
print("ZOVARK 100 ATTACK SIMULATION")
print("=" * 60)

# Load attacks
with open('/app/simulation_100_attacks.json') as f:
    attacks = json.load(f)

results = {
    'total': len(attacks),
    'processed': 0,
    'detected': 0,
    'missed': 0,
    'by_type': {},
    'risk_scores': [],
    'findings_count': [],
    'duration_ms': []
}

print(f"\nProcessing {len(attacks)} attacks...\n")

for i, attack in enumerate(attacks, 1):
    start_time = time.time()
    
    task_type = attack['task_type']
    siem_event = attack['siem_event']
    
    # Initialize type tracking
    if task_type not in results['by_type']:
        results['by_type'][task_type] = {'total': 0, 'detected': 0, 'avg_risk': 0}
    
    results['by_type'][task_type]['total'] += 1
    
    # Get detection tool
    tool = TOOL_MAP.get(task_type)
    
    if tool:
        try:
            result = tool(siem_event)
            risk_score = result.get('risk_score', 0)
            findings = result.get('findings', [])
            detected = risk_score >= 50
        except Exception as e:
            risk_score = 0
            findings = [f"Error: {str(e)}"]
            detected = False
    else:
        # Fallback for brute_force - use pattern matching
        raw_log = siem_event.get('raw_log', '').lower()
        if 'failed' in raw_log and ('500' in raw_log or 'attempt' in raw_log):
            risk_score = 75
            findings = ["Brute force pattern detected"]
            detected = True
        else:
            risk_score = 25
            findings = ["Low confidence brute force"]
            detected = False
    
    duration = (time.time() - start_time) * 1000
    
    # Update results
    results['processed'] += 1
    results['risk_scores'].append(risk_score)
    results['findings_count'].append(len(findings))
    results['duration_ms'].append(duration)
    
    if detected:
        results['detected'] += 1
        results['by_type'][task_type]['detected'] += 1
    else:
        results['missed'] += 1
    
    # Progress every 10
    if i % 10 == 0:
        print(f"  Processed {i}/{len(attacks)} attacks...")

# Calculate statistics
avg_risk = sum(results['risk_scores']) / len(results['risk_scores'])
avg_findings = sum(results['findings_count']) / len(results['findings_count'])
avg_duration = sum(results['duration_ms']) / len(results['duration_ms'])
detection_rate = results['detected'] / results['total'] * 100

# Summary
print("\n" + "=" * 60)
print("SIMULATION RESULTS")
print("=" * 60)
print(f"\nTotal Attacks: {results['total']}")
print(f"Detected: {results['detected']} ({detection_rate:.1f}%)")
print(f"Missed: {results['missed']}")
print(f"\nAverage Risk Score: {avg_risk:.1f}")
print(f"Average Findings: {avg_findings:.1f}")
print(f"Average Duration: {avg_duration:.3f}ms")

# By attack type
print("\n" + "-" * 60)
print("BY ATTACK TYPE")
print("-" * 60)
print(f"{'Attack Type':<25} {'Total':>6} {'Detected':>8} {'Rate':>6}")
print("-" * 60)

for attack_type, stats in sorted(results['by_type'].items()):
    rate = stats['detected'] / stats['total'] * 100 if stats['total'] > 0 else 0
    print(f"{attack_type:<25} {stats['total']:>6} {stats['detected']:>8} {rate:>5.1f}%")

# Risk distribution
print("\n" + "-" * 60)
print("RISK SCORE DISTRIBUTION")
print("-" * 60)
risk_ranges = {
    'Critical (80-100)': 0,
    'High (60-79)': 0,
    'Medium (40-59)': 0,
    'Low (20-39)': 0,
    'Minimal (0-19)': 0
}

for risk in results['risk_scores']:
    if risk >= 80:
        risk_ranges['Critical (80-100)'] += 1
    elif risk >= 60:
        risk_ranges['High (60-79)'] += 1
    elif risk >= 40:
        risk_ranges['Medium (40-59)'] += 1
    elif risk >= 20:
        risk_ranges['Low (20-39)'] += 1
    else:
        risk_ranges['Minimal (0-19)'] += 1

for range_name, count in risk_ranges.items():
    pct = count / results['total'] * 100
    bar = '█' * int(pct / 2)
    print(f"{range_name:<20} {count:>3} ({pct:>5.1f}%) {bar}")

# Missed attacks (if any)
if results['missed'] > 0:
    print("\n" + "-" * 60)
    print("MISSED ATTACKS (Risk < 50)")
    print("-" * 60)
    for i, attack in enumerate(attacks):
        if results['risk_scores'][i] < 50:
            print(f"  {attack['id']}: {attack['name']} (Risk: {results['risk_scores'][i]})")

# Save results
results['summary'] = {
    'detection_rate': detection_rate,
    'avg_risk': avg_risk,
    'avg_findings': avg_findings,
    'avg_duration_ms': avg_duration
}

with open('/app/simulation_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\n" + "=" * 60)
print("Results saved to /app/simulation_results.json")
print("=" * 60)

# Return code based on detection rate
if detection_rate >= 90:
    print("\n✅ EXCELLENT: Detection rate >= 90%")
    sys.exit(0)
elif detection_rate >= 75:
    print("\n⚠️ GOOD: Detection rate >= 75%")
    sys.exit(0)
else:
    print("\n❌ NEEDS IMPROVEMENT: Detection rate < 75%")
    sys.exit(1)
