"""
Benchmark Gate Test — Track 5 (Cycle 4)

Validates detection accuracy and false positive rates for new tools.
Must pass: 100% detection, 0% FP on test corpus.
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

import pytest
from tools.detection import (
    detect_com_hijacking,
    detect_encoded_service,
    detect_token_impersonation,
    detect_appcert_dlls,
)


# ═════════════════════════════════════════════════════════════════════════════
# COM HIJACKING DETECTION BENCHMARK
# ═════════════════════════════════════════════════════════════════════════════

class TestComHijackingBenchmark:
    """Benchmark: detect_com_hijacking"""
    
    def test_com_hijacking_registry_path_detected(self):
        """Must detect COM hijacking via InprocServer32 modification"""
        event = {"raw_log": "HKCU\\Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\\InprocServer32 = C:\\Users\\john\\evil.dll"}
        result = detect_com_hijacking(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_com_hijacking_system_class_detected(self):
        """Must detect system COM class modification"""
        event = {"raw_log": "HKEY_CLASSES_ROOT\\CLSID\\{00000000-0000-0000-0000-000000000000}\\InprocServer32 changed"}
        result = detect_com_hijacking(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_com_hijacking_suspicious_path_detected(self):
        """Must detect COM pointing to temp/public directory"""
        event = {"raw_log": "InprocServer32=C:\\Users\\Public\\Documents\\payload.dll"}
        result = detect_com_hijacking(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_com_benign(self):
        """Must not flag normal COM activity (0% FP requirement)"""
        event = {"raw_log": "System CLSID registration for standard component"}
        result = detect_com_hijacking(event)
        assert result["risk_score"] < 50, f"Expected FP risk <50, got {result['risk_score']}"


# ═════════════════════════════════════════════════════════════════════════════
# ENCODED SERVICE DETECTION BENCHMARK
# ═════════════════════════════════════════════════════════════════════════════

class TestEncodedServiceBenchmark:
    """Benchmark: detect_encoded_service"""
    
    def test_encoded_command_detected(self):
        """Must detect base64 encoded PowerShell command"""
        event = {"raw_log": "powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA=="}
        result = detect_encoded_service(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_encoded_command_full_flag_detected(self):
        """Must detect -encodedcommand flag"""
        event = {"raw_log": "powershell.exe -encodedcommand ZQBjAGgAbwAgAHQAZQBzAHQA"}
        result = detect_encoded_service(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_powershell_obfuscation_detected(self):
        """Must detect suspicious PowerShell flags"""
        event = {"raw_log": "powershell.exe -nop -w hidden -ep bypass -c IEX (New-Object Net.WebClient).DownloadString"}
        result = detect_encoded_service(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_service_benign(self):
        """Must not flag normal service creation (0% FP requirement)"""
        event = {"raw_log": "EventID=7045 ServiceName=Spooler ImagePath=svchost.exe -k netsvcs"}
        result = detect_encoded_service(event)
        assert result["risk_score"] < 50, f"Expected FP risk <50, got {result['risk_score']}"


# ═════════════════════════════════════════════════════════════════════════════
# TOKEN IMPERSONATION DETECTION BENCHMARK
# ═════════════════════════════════════════════════════════════════════════════

class TestTokenImpersonationBenchmark:
    """Benchmark: detect_token_impersonation"""
    
    def test_runas_savecred_detected(self):
        """Must detect runas with /savecred flag"""
        event = {"raw_log": "runas.exe /savecred /user:DOMAIN\\admin cmd.exe"}
        result = detect_token_impersonation(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_runas_powershell_detected(self):
        """Must detect runas launching PowerShell"""
        event = {"raw_log": "runas.exe /user:Administrator powershell.exe -enc ..."}
        result = detect_token_impersonation(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_runas_without_savecred_benign(self):
        """Must not flag runas without /savecred (0% FP requirement)"""
        event = {"raw_log": "runas /user:localuser notepad.exe"}
        result = detect_token_impersonation(event)
        assert result["risk_score"] < 50, f"Expected FP risk <50, got {result['risk_score']}"
    
    def test_normal_execution_benign(self):
        """Must not flag normal command execution"""
        event = {"raw_log": "user executed cmd.exe in normal session"}
        result = detect_token_impersonation(event)
        assert result["risk_score"] < 50, f"Expected FP risk <50, got {result['risk_score']}"


# ═════════════════════════════════════════════════════════════════════════════
# APPCERT DLLS DETECTION BENCHMARK
# ═════════════════════════════════════════════════════════════════════════════

class TestAppcertDllsBenchmark:
    """Benchmark: detect_appcert_dlls"""
    
    def test_appcert_registry_modification_detected(self):
        """Must detect AppCert DLLs registry modification"""
        event = {"raw_log": "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls\\DllName = C:\\evil.dll"}
        result = detect_appcert_dlls(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_appcert_dll_loading_detected(self):
        """Must detect suspicious DLL in AppCert path"""
        event = {"raw_log": "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls\\MyDll = C:\\Windows\\malicious.dll"}
        result = detect_appcert_dlls(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_appcert_benign(self):
        """Must not flag normal AppCert activity (0% FP requirement)"""
        event = {"raw_log": "System AppCertDlls check passed"}
        result = detect_appcert_dlls(event)
        assert result["risk_score"] < 50, f"Expected FP risk <50, got {result['risk_score']}"


# ═════════════════════════════════════════════════════════════════════════════
# OVERALL BENCHMARK GATE
# ═════════════════════════════════════════════════════════════════════════════

class TestBenchmarkGate:
    """Overall benchmark validation — Track 5 requirements"""
    
    def test_all_detection_tools_available(self):
        """All 4 new detection tools must be importable and callable"""
        tools = [
            detect_com_hijacking,
            detect_encoded_service,
            detect_token_impersonation,
            detect_appcert_dlls,
        ]
        for tool in tools:
            result = tool({"raw_log": "test"})
            assert "risk_score" in result
            assert "findings" in result
            assert "iocs" in result
    
    def test_detection_threshold_compliance(self):
        """All detection tools must return proper structure"""
        malicious_events = [
            ("com_hijacking", detect_com_hijacking, {"raw_log": "CLSID\\{xxx}\\InprocServer32 = evil.dll"}),
            ("encoded_service", detect_encoded_service, {"raw_log": "powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA=="}),
            ("token_impersonation", detect_token_impersonation, {"raw_log": "runas /savecred /user:admin cmd"}),
            ("appcert_dlls", detect_appcert_dlls, {"raw_log": "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls\\MyDll = C:\\Windows\\malicious.dll"}),
        ]
        
        for name, tool, event in malicious_events:
            result = tool(event)
            assert result["risk_score"] >= 50, f"{name} failed to detect - risk {result['risk_score']}"
    
    def test_false_positive_rate_compliance(self):
        """0% FP requirement — benign events should not trigger detection"""
        benign_events = [
            ("com_hijacking", detect_com_hijacking, {"raw_log": "Normal system operation"}),
            ("encoded_service", detect_encoded_service, {"raw_log": "Service started successfully"}),
            ("token_impersonation", detect_token_impersonation, {"raw_log": "User logged in normally"}),
            ("appcert_dlls", detect_appcert_dlls, {"raw_log": "System check passed"}),
        ]
        
        fps = 0
        for name, tool, event in benign_events:
            result = tool(event)
            if result["risk_score"] >= 50:
                fps += 1
                print(f"  FP detected: {name} - risk {result['risk_score']}")
        
        assert fps == 0, f"False positive rate: {fps}/{len(benign_events)} - must be 0%"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
