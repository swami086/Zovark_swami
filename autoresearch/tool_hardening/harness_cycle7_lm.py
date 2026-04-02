#!/usr/bin/env python3
"""Tool hardening harness for Cycle 7 - detect_lateral_movement"""
import sys
sys.path.insert(0, '/app')
from tools.detection import detect_lateral_movement

def run_harness(tool_name, tool_func, cases):
    print(f"=== {tool_name} Harness ===")
    
    passed = 0
    total = len(cases)
    
    for i, case in enumerate(cases):
        result = tool_func(case['input'])
        detected = result.get('risk_score', 0) > 50
        expected = case['expected_detected']
        status = 'OK' if detected == expected else 'FAIL'
        
        if detected == expected:
            passed += 1
        else:
            print(f"  {status} Case {i+1}: expected={expected}, got={detected}, risk={result.get('risk_score', 0)}")
    
    score = passed / total * 100
    print(f"  Fitness: {passed}/{total} ({score:.0f}%)")
    return passed, total

# Test cases for detect_lateral_movement
lateral_cases = [
    {"input": {"raw_log": "net use \\10.0.0.50\\ADMIN$ /user:DOMAIN\\admin P@ssw0rd!", "source_ip": "10.0.0.51", "destination_ip": "10.0.0.50"}, "expected_detected": True},
    {"input": {"raw_log": "psexec.exe \\10.0.0.52 -u admin -p password cmd.exe", "source_ip": "10.0.0.53", "destination_ip": "10.0.0.52"}, "expected_detected": True},
    {"input": {"raw_log": "wmic /node:10.0.0.54 process call create 'malware.exe'", "source_ip": "10.0.0.55", "destination_ip": "10.0.0.54"}, "expected_detected": True},
    {"input": {"raw_log": "scp file.txt user@10.0.0.56:/tmp/", "source_ip": "10.0.0.57", "destination_ip": "10.0.0.56"}, "expected_detected": True},
    {"input": {"raw_log": "Normal file access to local share", "source_ip": "10.0.0.58"}, "expected_detected": False}
]

p, t = run_harness('detect_lateral_movement', detect_lateral_movement, lateral_cases)
print(f"")
print(f"=== Overall ===")
print(f"Total: {p}/{t} ({p/t*100:.0f}%)")
