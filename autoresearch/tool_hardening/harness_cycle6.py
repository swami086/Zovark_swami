#!/usr/bin/env python3
"""Tool hardening harness for Cycle 6 - Track 4"""
import sys
sys.path.insert(0, '/app')
from tools.detection import detect_phishing, detect_c2, detect_data_exfil

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

# Test cases for detect_phishing
phishing_cases = [
    {"input": {"raw_log": "http://evil-bank.com/login.html credential harvester from: victim@company.com"}, "expected_detected": True},
    {"input": {"raw_log": "Subject: Urgent! Verify your account now! Click here: bit.ly/suspicious"}, "expected_detected": True},
    {"input": {"raw_log": "URGENT: immediate action required within 24 hours! Click here to verify!"}, "expected_detected": True},
    {"input": {"raw_log": "Normal business email regarding quarterly report"}, "expected_detected": False},
    {"input": {"raw_log": "Internal IT notification: Password expires in 30 days per company policy"}, "expected_detected": False}
]

# Test cases for detect_c2
c2_cases = [
    {"input": {"raw_log": "Beacon interval=60s jitter=0.3 to 192.168.1.100:4444", "source_ip": "10.0.2.10"}, "expected_detected": True},
    {"input": {"raw_log": "HTTPS connection to known-bad-domain.com with User-Agent: Mozilla/5.0 (compatible; Cobalt Strike)"}, "expected_detected": True},
    {"input": {"raw_log": "DNS query type=TXT for aaaabbbbccccdddd.evil.com"}, "expected_detected": True},
    {"input": {"raw_log": "Regular HTTPS browsing to google.com"}, "expected_detected": False},
    {"input": {"raw_log": "Normal DNS resolution for microsoft.com"}, "expected_detected": False}
]

# Test cases for detect_data_exfil
exfil_cases = [
    {"input": {"raw_log": "Large outbound transfer: 5GB to wetransfer.com", "source_ip": "10.0.3.10", "bytes_out": 5368709120}, "expected_detected": True},
    {"input": {"raw_log": "rar.exe a -p secret.zip C:\\data\\*.pdf uploaded 5GB to dropbox.com"}, "expected_detected": True},
    {"input": {"raw_log": "Multiple failed auth attempts then successful upload to personal drive"}, "expected_detected": True},
    {"input": {"raw_log": "Normal file sync to corporate OneDrive", "bytes_out": 10485760}, "expected_detected": False},
    {"input": {"raw_log": "Internal file share access", "source_ip": "10.0.3.11"}, "expected_detected": False}
]

tools = [
    ('detect_phishing', detect_phishing, phishing_cases),
    ('detect_c2', detect_c2, c2_cases),
    ('detect_data_exfil', detect_data_exfil, exfil_cases),
]

total_passed = 0
total_cases = 0
for name, func, cases in tools:
    p, t = run_harness(name, func, cases)
    total_passed += p
    total_cases += t

print(f"")
print(f"=== Overall Track 4 (Cycle 6) ===")
print(f"Total: {total_passed}/{total_cases} ({total_passed/total_cases*100:.0f}%)")
