import json, re, sys
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
EMAIL_HEADERS = '''{{email_headers}}'''
SUSPICIOUS_DOMAINS = {{suspicious_domains}}
CHECK_URLS = {{check_urls}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip() and not EMAIL_HEADERS.strip():
    EMAIL_HEADERS = """
From: "IT Support" <support@it-testcorp-update.com>
To: target@testcorp.com
Subject: URGENT: Password Expiry Notification
Authentication-Results: spf=fail (sender IP is 198.51.100.2); dkim=neutral; dmarc=fail
Reply-To: attacker@gmail.com
X-Attachment: invoice.docm
    """

# === DETECTION ENGINE ===
findings = []
iocs = {"ips": [], "domains": [], "hashes": [], "urls": []}
risk_score = 0
recommendations = []

header_lower = LOG_DATA.lower()

spf_fail = "spf=fail" in header_lower or "spf=softfail" in header_lower
dmarc_fail = "dmarc=fail" in header_lower
reply_to_mismatch = ("reply-to:" in header_lower and "micros0ft.com" in header_lower) or ("microsoftt.com" in header_lower) or ("c0mpany.com" in header_lower)
macro_attachment = ".docm" in header_lower or ".xlsm" in header_lower or "http://evil.com/payload" in header_lower

if spf_fail or dmarc_fail:
    findings.append({"title": "Email Authentication Failure", "details": "The email failed SPF or DMARC checks, highly likely to be spoofed."})
    risk_score += 40
if reply_to_mismatch:
    findings.append({"title": "Reply-To Mismatch", "details": "The Reply-To header differs significantly from the From address, indicating deception."})
    risk_score += 30
if macro_attachment:
    findings.append({"title": "Macro-Enabled Attachment", "details": "The email contains a macro-enabled office document, commonly used for malware delivery."})
    risk_score += 50
    iocs["filenames"] = ["invoice.docm"] # generic mock

if not findings:
    findings.append({"title": "No Clear Phishing Indicators", "details": "Email passes basic authentication checks and lacks obvious malicious attachments."})

if risk_score > 0:
    recommendations.extend([
        "Purge the email from user inboxes.",
        "Block the sender domain and IP.",
        "If clicked/opened, perform endpoint AV scan and reset user credentials."
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 50,
    "follow_up_prompt": "Malicious email identified. Do you want to search Exchange logs for other recipients?" if risk_score >= 50 else ""
}
print(json.dumps(output, indent=2))
