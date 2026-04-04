#!/usr/bin/env python3
"""Tool hardening harness for Cycle 5 - Track 4"""
import sys
sys.path.insert(0, '/app')
from tools.detection import detect_kerberoasting, detect_golden_ticket, detect_ransomware

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

# Test cases for detect_kerberoasting
kerberoasting_cases = [
    {"input": {"raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433", "source_ip": "10.0.1.50", "username": "svc_sql"}, "expected_detected": True},
    {"input": {"raw_log": "EventID=4769 TicketEncryptionType=0x12 ServiceName=HTTP/web01", "source_ip": "10.0.1.51", "username": "svc_web"}, "expected_detected": False},
    {"input": {"raw_log": "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt", "source_ip": "10.0.1.52", "username": "jdoe"}, "expected_detected": False},
    {"input": {"raw_log": "Normal authentication activity", "source_ip": "10.0.1.53", "username": "normal_user"}, "expected_detected": False},
    {"input": {"raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=CIFS/file01", "source_ip": "10.0.1.54", "username": "attacker"}, "expected_detected": True}
]

# Test cases for detect_golden_ticket
golden_ticket_cases = [
    {"input": {"raw_log": "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt/DOMAIN.COM", "source_ip": "10.0.1.60", "username": "admin"}, "expected_detected": True},
    {"input": {"raw_log": "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt", "source_ip": "10.0.1.61", "username": "legit_user"}, "expected_detected": True},
    {"input": {"raw_log": "EventID=4768 TicketEncryptionType=0x12 ServiceName=krbtgt", "source_ip": "10.0.1.62", "username": "normal"}, "expected_detected": False},
    {"input": {"raw_log": "EventID=4624 LogonType=3", "source_ip": "10.0.1.63", "username": "workstation$"}, "expected_detected": False},
    {"input": {"raw_log": "EventID=4768 TicketOptions=0x50800010 Lifetime=600h", "source_ip": "10.0.1.64", "username": "svc_backup"}, "expected_detected": True}
]

# Test cases for detect_ransomware
ransomware_cases = [
    {"input": {"raw_log": "vssadmin delete shadows /all /quiet"}, "expected_detected": True},
    {"input": {"raw_log": "wmic shadowcopy delete"}, "expected_detected": True},
    {"input": {"raw_log": "file.doc.locked file.xls.encrypted"}, "expected_detected": True},
    {"input": {"raw_log": "README.txt ransom payment bitcoin"}, "expected_detected": True},
    {"input": {"raw_log": "Service started normally PID=1234"}, "expected_detected": False}
]

tools = [
    ('detect_kerberoasting', detect_kerberoasting, kerberoasting_cases),
    ('detect_golden_ticket', detect_golden_ticket, golden_ticket_cases),
    ('detect_ransomware', detect_ransomware, ransomware_cases),
]

total_passed = 0
total_cases = 0
for name, func, cases in tools:
    p, t = run_harness(name, func, cases)
    total_passed += p
    total_cases += t

print(f"")
print(f"=== Overall Track 4 (Cycle 5) ===")
print(f"Total: {total_passed}/{total_cases} ({total_passed/total_cases*100:.0f}%)")
