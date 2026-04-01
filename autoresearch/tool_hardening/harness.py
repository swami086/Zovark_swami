#!/usr/bin/env python3
"""Tool hardening harness for Cycle 4 - Track 4"""

import sys
sys.path.insert(0, '/app')
from tools.detection import detect_com_hijacking, detect_encoded_service, detect_token_impersonation

# Test detect_com_hijacking
print("=== detect_com_hijacking ===")
test_cases = [
    {"raw_log": "HKCU\\Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\\InprocServer32 changed to C:\\Users\\john\\evil.dll", "expected": True},
    {"raw_log": "Normal registry activity, no COM paths", "expected": False},
]
passed = 0
for tc in test_cases:
    result = detect_com_hijacking({"raw_log": tc["raw_log"]})
    detected = result.get('risk_score', 0) > 50
    status = 'OK' if detected == tc['expected'] else 'FAIL'
    if detected == tc['expected']:
        passed += 1
    print(f"  {status}: risk={result.get('risk_score', 0)}")
print(f"  Fitness: {passed}/{len(test_cases)} ({passed/len(test_cases)*100:.0f}%)")

# Test detect_encoded_service  
print("\n=== detect_encoded_service ===")
test_cases = [
    {"raw_log": "powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==", "expected": True},
    {"raw_log": "Service created: ImagePath=svchost.exe -k netsvcs", "expected": False},
]
passed = 0
for tc in test_cases:
    result = detect_encoded_service({"raw_log": tc["raw_log"]})
    detected = result.get('risk_score', 0) > 50
    status = 'OK' if detected == tc['expected'] else 'FAIL'
    if detected == tc['expected']:
        passed += 1
    print(f"  {status}: risk={result.get('risk_score', 0)}")
print(f"  Fitness: {passed}/{len(test_cases)} ({passed/len(test_cases)*100:.0f}%)")

# Test detect_token_impersonation
print("\n=== detect_token_impersonation ===")
test_cases = [
    {"raw_log": "runas.exe /savecred /user:DOMAIN\\admin cmd.exe", "expected": True},
    {"raw_log": "runas /user:localuser notepad.exe", "expected": False},
]
passed = 0
for tc in test_cases:
    result = detect_token_impersonation({"raw_log": tc["raw_log"]})
    detected = result.get('risk_score', 0) > 50
    status = 'OK' if detected == tc['expected'] else 'FAIL'
    if detected == tc['expected']:
        passed += 1
    print(f"  {status}: risk={result.get('risk_score', 0)}")
print(f"  Fitness: {passed}/{len(test_cases)} ({passed/len(test_cases)*100:.0f}%)")

print("\n=== Track 4 Complete ===")
