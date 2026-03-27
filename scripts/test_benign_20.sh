#!/bin/bash
# Benign calibration test: 20 diverse benign system events
API="http://localhost:8090"
TK=$(curl -s -X POST $API/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

BENIGN_EVENTS=(
  '{"title":"Windows Update","source_ip":"10.0.0.5","username":"SYSTEM","rule_name":"ScheduledTask","raw_log":"wuauclt.exe /detectnow Status=Success"}'
  '{"title":"Scheduled Backup","source_ip":"10.0.0.10","username":"backup_svc","rule_name":"Backup","raw_log":"Veeam backup job completed successfully for VM-PROD-01"}'
  '{"title":"User Login","source_ip":"192.168.1.50","username":"jsmith","rule_name":"Login","raw_log":"User jsmith logged in from 192.168.1.50 at 09:15 business hours"}'
  '{"title":"DNS Lookup","source_ip":"10.0.0.5","username":"SYSTEM","rule_name":"DNS","raw_log":"DNS query for windowsupdate.microsoft.com from 10.0.0.5 Type=A"}'
  '{"title":"NTP Sync","source_ip":"10.0.0.1","username":"SYSTEM","rule_name":"NTP","raw_log":"NTP sync with time.windows.com offset=0.002s stratum=2"}'
  '{"title":"AV Scan","source_ip":"10.0.1.25","username":"SYSTEM","rule_name":"AV","raw_log":"Defender scheduled scan completed. 0 threats found. Duration: 45min"}'
  '{"title":"Software Inventory","source_ip":"10.0.0.5","username":"sccm_svc","rule_name":"SCCM","raw_log":"SCCM hardware inventory cycle completed for WS-HR-01"}'
  '{"title":"Certificate Renewal","source_ip":"10.0.0.3","username":"certmgr","rule_name":"PKI","raw_log":"Certificate CN=webapp.corp.local renewed. Expiry: 2027-03-24"}'
  '{"title":"Log Rotation","source_ip":"10.0.0.5","username":"logrotate","rule_name":"Maintenance","raw_log":"logrotate: rotated 15 log files. Freed 2.3GB disk space"}'
  '{"title":"Health Check","source_ip":"10.0.0.100","username":"monitoring","rule_name":"Healthcheck","raw_log":"Nagios health check: all 42 services OK. Uptime: 99.99%"}'
  '{"title":"Patch Management","source_ip":"10.0.0.5","username":"wsus_svc","rule_name":"WSUS","raw_log":"WSUS approved 3 patches for server group. KB5034441 installed."}'
  '{"title":"Config Sync","source_ip":"10.0.0.20","username":"puppet","rule_name":"ConfigMgmt","raw_log":"Puppet agent run completed. 0 changes applied. Catalog version 1247."}'
  '{"title":"LDAP Query","source_ip":"10.0.1.50","username":"app_svc","rule_name":"LDAP","raw_log":"LDAP search base=DC=corp,DC=local filter=(sAMAccountName=jsmith) result=1"}'
  '{"title":"SNMP Poll","source_ip":"10.0.0.100","username":"snmp_reader","rule_name":"SNMP","raw_log":"SNMP GET .1.3.6.1.2.1.1.3 from switch-core-01. sysUpTime: 45 days"}'
  '{"title":"Bandwidth Test","source_ip":"10.0.0.5","username":"netops","rule_name":"iPerf","raw_log":"iPerf test to 10.0.0.200: 940 Mbps. Packet loss: 0%. Jitter: 0.1ms"}'
  '{"title":"File Integrity","source_ip":"10.0.0.5","username":"tripwire","rule_name":"FIM","raw_log":"Tripwire scan completed. 0 violations detected. Files checked: 12847"}'
  '{"title":"Business Login","source_ip":"192.168.1.75","username":"mthompson","rule_name":"Auth","raw_log":"Successful login for mthompson from 192.168.1.75 at 08:30 Mon"}'
  '{"title":"Password Change","source_ip":"192.168.1.75","username":"mthompson","rule_name":"Auth","raw_log":"mthompson changed password. Self-service portal. Policy compliant."}'
  '{"title":"VPN Connect","source_ip":"203.0.113.50","username":"jdoe","rule_name":"VPN","raw_log":"VPN connection established for jdoe from 203.0.113.50 via AnyConnect"}'
  '{"title":"Print Job","source_ip":"10.0.1.25","username":"jsmith","rule_name":"Print","raw_log":"Print job 4421 completed on HP-LaserJet-4F. Pages: 3. User: jsmith"}'
)

echo "=== Submitting 20 benign alerts ==="
TASK_IDS=()
for i in "${!BENIGN_EVENTS[@]}"; do
  SIEM="${BENIGN_EVENTS[$i]}"
  RESP=$(curl -s -X POST $API/api/v1/tasks -H "Authorization: Bearer $TK" -H "Content-Type: application/json" \
    -d "{\"task_type\":\"system_event\",\"input\":{\"prompt\":\"Routine system event\",\"severity\":\"low\",\"siem_event\":$SIEM}}")
  TID=$(echo "$RESP" | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
  TASK_IDS+=("$TID")
  echo "  [$((i+1))/20] $TID"
  sleep 1
done

echo ""
echo "=== Waiting 120s for completion ==="
sleep 120

echo ""
echo "=== RESULTS ==="
TK2=$(curl -s -X POST $API/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

BENIGN=0; SUSPICIOUS=0; TP=0; PENDING=0
for TID in "${TASK_IDS[@]}"; do
  ROW=$(docker compose exec -T postgres psql -U zovarc -d zovarc -t -c "SELECT status, COALESCE(output->>'verdict','?'), COALESCE((output->>'risk_score')::int, -1) FROM agent_tasks WHERE id='$TID';" 2>/dev/null | tr -d ' ')
  STATUS=$(echo "$ROW" | cut -d'|' -f1)
  VERDICT=$(echo "$ROW" | cut -d'|' -f2)
  RISK=$(echo "$ROW" | cut -d'|' -f3)
  if [ "$STATUS" = "pending" ]; then PENDING=$((PENDING+1)); fi
  if [ "$VERDICT" = "benign" ]; then BENIGN=$((BENIGN+1)); fi
  if [ "$VERDICT" = "suspicious" ]; then SUSPICIOUS=$((SUSPICIOUS+1)); fi
  if [ "$VERDICT" = "true_positive" ]; then TP=$((TP+1)); fi
done

echo "Benign: $BENIGN/20"
echo "Suspicious: $SUSPICIOUS/20"
echo "True Positive: $TP/20"
echo "Pending: $PENDING/20"
echo ""
if [ $BENIGN -ge 18 ]; then echo "PASS: $BENIGN/20 benign (target: 18+)"; else echo "FAIL: only $BENIGN/20 benign (target: 18+)"; fi
