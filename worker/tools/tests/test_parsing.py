"""Tests for parsing tools."""
import pytest
from tools.parsing import (
    parse_windows_event, parse_syslog, parse_auth_log,
    parse_dns_query, parse_http_request,
)


class TestParseWindowsEvent:
    def test_kerberos_event(self):
        result = parse_windows_event("EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433 ClientAddress=10.0.1.50")
        assert "EventID" in result
        assert result["EventID"] == "4769"
        assert "TicketEncryptionType" in result
        assert "ServiceName" in result
        assert "ClientAddress" in result

    def test_no_fields(self):
        assert parse_windows_event("Just prose no fields") == {}

    def test_empty(self):
        assert parse_windows_event("") == {}


class TestParseSyslog:
    def test_standard_syslog(self):
        result = parse_syslog("Mar 30 14:22:01 webserver sshd[12345]: Failed password for root from 10.0.0.1")
        assert "hostname" in result
        assert result["hostname"] == "webserver"
        assert "process" in result
        assert result["process"] == "sshd"
        assert "message" in result

    def test_not_syslog(self):
        assert parse_syslog("Not syslog") == {}


class TestParseAuthLog:
    def test_failed_login(self):
        result = parse_auth_log("Failed password for root from 185.220.101.45 port 22 ssh2")
        assert result["action"] == "failure"
        assert result["username"] == "root"
        assert result["source_ip"] == "185.220.101.45"

    def test_success_login(self):
        result = parse_auth_log("Accepted publickey for admin from 10.0.0.5 port 54321")
        assert result["action"] == "success"
        assert result["username"] == "admin"

    def test_no_auth_data(self):
        assert parse_auth_log("Random text") == {}


class TestParseDnsQuery:
    def test_dns_query(self):
        result = parse_dns_query("DNS query aGVsbG8.evil-cdn.net from 10.0.0.5 QueryType=TXT ResponseSize=4096")
        assert "query_name" in result
        assert "source_ip" in result

    def test_not_dns(self):
        assert parse_dns_query("Not DNS") == {}


class TestParseHttpRequest:
    def test_clf_format(self):
        result = parse_http_request('10.0.0.1 - - [30/Mar/2026] "GET /api/admin HTTP/1.1" 403 150 "-" "Mozilla/5.0"')
        assert "method" in result
        assert result["method"] == "GET"
        assert "path" in result
        assert result["path"] == "/api/admin"
        assert "status_code" in result
        assert "source_ip" in result

    def test_not_http(self):
        assert parse_http_request("Not HTTP") == {}
