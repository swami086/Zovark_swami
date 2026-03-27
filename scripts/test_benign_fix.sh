#!/bin/bash
API="http://localhost:8090"
TK=$(curl -s -X POST $API/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

echo "=== 10 BENIGN ALERTS ==="
for i in 1 2 3 4 5 6 7 8 9 10; do
  case $i in
    1) TITLE="Windows Update"; LOG="TaskName=WindowsUpdate Scheduler=SYSTEM Host=WS-01 Status=Success" ;;
    2) TITLE="Scheduled Backup"; LOG="BackupJob=NightlyBackup Status=Completed Duration=45min 0errors" ;;
    3) TITLE="Certificate Renewal"; LOG="Certificate CN=api.corp.local renewed valid 365days Status=Success" ;;
    4) TITLE="Password Change"; LOG="jsmith changed own password via self-service portal at 09:30 Monday" ;;
    5) TITLE="User Login"; LOG="User jsmith logged in from 192.168.1.50 at 09:15 business hours" ;;
    6) TITLE="NTP Sync"; LOG="NTP sync pool.ntp.org offset=0.002s stratum=2 Status=Success" ;;
    7) TITLE="Software Inventory"; LOG="SCCM hardware inventory cycle completed 247 packages on WS-HR-01" ;;
    8) TITLE="Health Check"; LOG="Nagios health check api-gateway status=healthy uptime=99.99pct" ;;
    9) TITLE="LDAP Query"; LOG="LDAP search base=dc=corp,dc=local filter=sAMAccountName=jsmith results=42" ;;
    10) TITLE="Log Rotation"; LOG="logrotate /var/log/syslog rotated compressed archived freed 2GB" ;;
  esac
  curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
    -d "{\"task_type\":\"system_event\",\"input\":{\"prompt\":\"Routine: $TITLE\",\"severity\":\"low\",\"siem_event\":{\"title\":\"$TITLE\",\"source_ip\":\"10.0.0.$i\",\"username\":\"SYSTEM\",\"rule_name\":\"Routine\",\"raw_log\":\"$LOG\"}}}" > /dev/null
  echo "  [$i] $TITLE"
  sleep 1
done

echo ""
echo "=== 5 ATTACK ALERTS ==="
# Refresh token
TK=$(curl -s -X POST $API/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"brute_force","input":{"prompt":"SSH brute force","severity":"critical","siem_event":{"title":"SSH Brute Force 500 attempts","source_ip":"185.220.101.45","username":"root","rule_name":"BruteForce","raw_log":"500 Failed password for root from 185.220.101.45 port 22 ssh2 in 60s"}}}' > /dev/null
echo "  [1] Brute Force"

curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"phishing","input":{"prompt":"Phishing email","severity":"high","siem_event":{"title":"Phishing URL Clicked","source_ip":"10.0.1.50","username":"jsmith","rule_name":"PhishDetect","raw_log":"User jsmith clicked https://micros0ft-update.xyz/login.php Attachment: invoice.pdf.exe immediate action required account suspended"}}}' > /dev/null
echo "  [2] Phishing"

curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"lateral_movement","input":{"prompt":"Pass the Hash","severity":"critical","siem_event":{"title":"Lateral Movement PtH","source_ip":"10.0.0.50","destination_ip":"10.0.0.200","username":"svc_backup","rule_name":"PtH","raw_log":"EventID=4624 LogonType=9 SourceIP=10.0.0.50 User=svc_backup NTLM pass-the-hash mimikatz.exe"}}}' > /dev/null
echo "  [3] Lateral Movement"

curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"ransomware_triage","input":{"prompt":"Ransomware","severity":"critical","siem_event":{"title":"Shadow Copy Deletion","source_ip":"10.0.0.15","username":"admin","rule_name":"Ransomware","raw_log":"vssadmin.exe delete shadows /all /quiet bcdedit /set recoveryenabled no FileRename .encrypted"}}}' > /dev/null
echo "  [4] Ransomware"

curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
  -d '{"task_type":"credential_access","input":{"prompt":"Kerberoasting","severity":"high","siem_event":{"title":"Kerberoasting SPN Enum","source_ip":"10.0.1.45","username":"jsmith","rule_name":"T1558.003","raw_log":"EventID=4769 ServiceName=MSSQLSvc/db.corp.local TicketEncryptionType=0x17 RC4_DOWNGRADE=true RequestCount=47"}}}' > /dev/null
echo "  [5] Kerberoasting"

echo ""
echo "All 15 submitted."
