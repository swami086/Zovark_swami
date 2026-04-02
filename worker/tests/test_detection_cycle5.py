"""
Cycle 5 Detection Tool Tests — Track 6
Tests for detect_kerberoasting, detect_golden_ticket, detect_ransomware
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

import pytest
from tools.detection import detect_kerberoasting, detect_golden_ticket, detect_ransomware


class TestKerberoastingDetection:
    """Tests for detect_kerberoasting tool"""
    
    def test_rc4_tgs_request_detected(self):
        """Must detect RC4 encryption in TGS request"""
        event = {
            "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433",
            "source_ip": "10.0.1.50",
            "username": "svc_sql"
        }
        result = detect_kerberoasting(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
        assert any("RC4" in f for f in result["findings"])
    
    def test_aes_encryption_not_flagged(self):
        """Must not flag AES encryption (strong)"""
        event = {
            "raw_log": "EventID=4769 TicketEncryptionType=0x12 ServiceName=HTTP/web01",
            "source_ip": "10.0.1.51",
            "username": "svc_web"
        }
        result = detect_kerberoasting(event)
        assert result["risk_score"] < 50, f"Expected FP risk <50, got {result['risk_score']}"
    
    def test_krbtgt_not_kerberoasting(self):
        """Must not flag TGT requests (krbtgt) as kerberoasting"""
        event = {
            "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=krbtgt",
            "source_ip": "10.0.1.52",
            "username": "jdoe"
        }
        result = detect_kerberoasting(event)
        assert result["risk_score"] < 50, f"Expected lower risk for krbtgt, got {result['risk_score']}"
    
    def test_cifs_service_detected(self):
        """Must detect RC4 for CIFS service"""
        event = {
            "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=CIFS/file01",
            "source_ip": "10.0.1.54",
            "username": "attacker"
        }
        result = detect_kerberoasting(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_auth_benign(self):
        """Must not flag normal authentication"""
        event = {
            "raw_log": "Normal authentication activity",
            "source_ip": "10.0.1.53",
            "username": "normal_user"
        }
        result = detect_kerberoasting(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


class TestGoldenTicketDetection:
    """Tests for detect_golden_ticket tool"""
    
    def test_rc4_tgt_krbtgt_detected(self):
        """Must detect RC4 TGT request for krbtgt"""
        event = {
            "raw_log": "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt/DOMAIN.COM",
            "source_ip": "10.0.1.60",
            "username": "admin"
        }
        result = detect_golden_ticket(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_tgt_without_rc4_not_flagged(self):
        """Must not flag TGT without RC4 as strongly"""
        event = {
            "raw_log": "EventID=4768 TicketEncryptionType=0x12 ServiceName=krbtgt",
            "source_ip": "10.0.1.62",
            "username": "normal"
        }
        result = detect_golden_ticket(event)
        assert result["risk_score"] < 50, f"Expected lower risk without RC4, got {result['risk_score']}"
    
    def test_abnormal_lifetime_detected(self):
        """Must detect abnormally long ticket lifetime"""
        event = {
            "raw_log": "EventID=4768 TicketOptions=0x50800010 Lifetime=600h",
            "source_ip": "10.0.1.64",
            "username": "svc_backup"
        }
        result = detect_golden_ticket(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50 for abnormal lifetime, got {result['risk_score']}"
    
    def test_normal_logon_benign(self):
        """Must not flag normal logon"""
        event = {
            "raw_log": "EventID=4624 LogonType=3",
            "source_ip": "10.0.1.63",
            "username": "workstation$"
        }
        result = detect_golden_ticket(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


class TestRansomwareDetection:
    """Tests for detect_ransomware tool"""
    
    def test_vssadmin_delete_detected(self):
        """Must detect vssadmin shadow deletion"""
        event = {"raw_log": "vssadmin delete shadows /all /quiet"}
        result = detect_ransomware(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
        assert any("shadow" in f.lower() for f in result["findings"])
    
    def test_wmic_shadow_delete_detected(self):
        """Must detect WMI shadow copy deletion"""
        event = {"raw_log": "wmic shadowcopy delete"}
        result = detect_ransomware(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_ransom_extension_detected(self):
        """Must detect ransomware file extensions"""
        event = {"raw_log": "file.doc.locked file.xls.encrypted"}
        result = detect_ransomware(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_ransom_note_detected(self):
        """Must detect ransom note language"""
        event = {"raw_log": "README.txt ransom payment bitcoin"}
        result = detect_ransomware(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_service_benign(self):
        """Must not flag normal service activity"""
        event = {"raw_log": "Service started normally PID=1234"}
        result = detect_ransomware(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
