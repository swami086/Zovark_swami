"""
Cycle 6 Detection Tool Tests — Track 6
Tests for detect_phishing, detect_c2, detect_data_exfil
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

import pytest
from tools.detection import detect_phishing, detect_c2, detect_data_exfil


class TestPhishingDetection:
    """Tests for detect_phishing tool"""
    
    def test_credential_harvester_detected(self):
        """Must detect credential harvesting page"""
        event = {"raw_log": "http://evil-bank.com/login.html credential harvester from: victim@company.com"}
        result = detect_phishing(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_urgent_url_detected(self):
        """Must detect urgent language with URL"""
        event = {"raw_log": "Subject: Urgent! Verify your account now! Click here: bit.ly/suspicious"}
        result = detect_phishing(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_urgency_timeframe_detected(self):
        """Must detect urgency with timeframe"""
        event = {"raw_log": "URGENT: immediate action required within 24 hours! Click here to verify!"}
        result = detect_phishing(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_email_benign(self):
        """Must not flag normal business email"""
        event = {"raw_log": "Normal business email regarding quarterly report"}
        result = detect_phishing(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"
    
    def test_internal_notification_benign(self):
        """Must not flag internal IT notification"""
        event = {"raw_log": "Internal IT notification: Password expires in 30 days per company policy"}
        result = detect_phishing(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


class TestC2Detection:
    """Tests for detect_c2 tool"""
    
    def test_beacon_interval_detected(self):
        """Must detect beacon interval pattern"""
        event = {
            "raw_log": "Beacon interval=60s jitter=0.3 to 192.168.1.100:4444",
            "source_ip": "10.0.2.10"
        }
        result = detect_c2(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_cobalt_strike_ua_detected(self):
        """Must detect Cobalt Strike User-Agent"""
        event = {"raw_log": "HTTPS connection to domain.com with User-Agent: Mozilla/5.0 (compatible; Cobalt Strike)"}
        result = detect_c2(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_dns_tunnel_detected(self):
        """Must detect DNS tunneling"""
        event = {"raw_log": "DNS query type=TXT for aaaabbbbccccdddd.evil.com"}
        result = detect_c2(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_https_benign(self):
        """Must not flag normal HTTPS"""
        event = {"raw_log": "Regular HTTPS browsing to google.com"}
        result = detect_c2(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"
    
    def test_normal_dns_benign(self):
        """Must not flag normal DNS"""
        event = {"raw_log": "Normal DNS resolution for microsoft.com"}
        result = detect_c2(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


class TestDataExfilDetection:
    """Tests for detect_data_exfil tool"""
    
    def test_large_transfer_detected(self):
        """Must detect large data transfer"""
        event = {
            "raw_log": "Large outbound transfer: 5GB to wetransfer.com",
            "source_ip": "10.0.3.10",
            "bytes_out": 5368709120
        }
        result = detect_data_exfil(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_archive_cloud_exfil_detected(self):
        """Must detect archive to cloud exfiltration"""
        event = {"raw_log": "rar.exe a -p secret.zip C:\\data\\*.pdf uploaded 5GB to dropbox.com"}
        result = detect_data_exfil(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_suspicious_access_pattern_detected(self):
        """Must detect suspicious access then upload"""
        event = {"raw_log": "Multiple failed auth attempts then successful upload to personal drive"}
        result = detect_data_exfil(event)
        assert result["risk_score"] >= 50, f"Expected risk >=50, got {result['risk_score']}"
    
    def test_normal_file_sync_benign(self):
        """Must not flag normal file sync"""
        event = {
            "raw_log": "Normal file sync to corporate OneDrive",
            "bytes_out": 10485760
        }
        result = detect_data_exfil(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"
    
    def test_internal_share_benign(self):
        """Must not flag internal file share"""
        event = {
            "raw_log": "Internal file share access",
            "source_ip": "10.0.3.11"
        }
        result = detect_data_exfil(event)
        assert result["risk_score"] < 50, f"Expected benign risk <50, got {result['risk_score']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
