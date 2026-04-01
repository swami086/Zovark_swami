#!/usr/bin/env python3
"""Tool hardening harness for Cycle 4 - Track 4"""

import json
import sys
sys.path.insert(0, '/app/worker')
from tools.detection import detect_com_hijacking, detect_encoded_service, detect_token_impersonation

def run_harness(tool_name, tool_func, cases_file):
    print(f"=== {tool_name} Harness ===")
    with open(cases_file) as f:
        cases = json.load(f)
    
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

# Run harness on all 3 tools
tools = [
    ('detect_com_hijacking', detect_com_hijacking, 'autoresearch/tool_hardening/edge_cases/detect_com_hijacking.json'),
    ('detect_encoded_service', detect_encoded_service, 'autoresearch/tool_hardening/edge_cases/detect_encoded_service.json'),
    ('detect_token_impersonation', detect_token_impersonation, 'autoresearch/tool_hardening/edge_cases/detect_token_impersonation.json'),
]

total_passed = 0
total_cases = 0
for name, func, file in tools:
    p, t = run_harness(name, func, file)
    total_passed += p
    total_cases += t

print("")
print("=== Overall Track 4 ===")
print(f"Total: {total_passed}/{total_cases} ({total_passed/total_cases*100:.0f}%)")
