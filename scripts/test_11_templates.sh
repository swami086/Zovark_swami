#!/bin/bash
# Test all 11 skill templates

TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

docker compose exec -T redis redis-cli -a hydra-redis-dev-2026 FLUSHDB 2>/dev/null

echo "=== Submitting 11 investigations ==="

submit() {
  local num=$1 name=$2 data=$3
  local R=$(curl -s -X POST http://localhost:8090/api/v1/tasks -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$data")
  local TID=$(echo "$R" | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
  echo "[$num] $name: $TID"
  echo "$TID" >> /tmp/hydra_11_ids.txt
}

rm -f /tmp/hydra_11_ids.txt

submit 1 phishing '{"task_type":"phishing_investigation","input":{"prompt":"Investigate phishing email","severity":"high","siem_event":{"raw_log":"From: ceo@evil.com Subject: Wire Transfer Click: http://phish.evil.com src_ip=203.0.113.50 hostname=MAIL-GW-01 username=jdoe","source_ip":"203.0.113.50","destination_ip":"10.0.0.5","hostname":"MAIL-GW-01","username":"jdoe"}}}'

submit 2 ransomware '{"task_type":"ransomware_triage","input":{"prompt":"Investigate ransomware","severity":"critical","siem_event":{"raw_log":"vssadmin.exe delete shadows /all /quiet\nFileRename: Budget.xlsx -> Budget.xlsx.encrypted\nFileRename: HR.pdf -> HR.pdf.encrypted\nFileCreate: README_DECRYPT.txt","source_ip":"10.0.0.15","destination_ip":"10.0.0.50","hostname":"SRV-FILE-01","username":"admin"}}}'

submit 3 data_exfil '{"task_type":"data_exfiltration_detection","input":{"prompt":"Investigate data exfiltration","severity":"high","siem_event":{"raw_log":"DNS query=encoded.exfil.evil.com type=TXT src_ip=10.0.0.33\nHTTPS POST bytes_out=52428800 dst_ip=198.51.100.99","source_ip":"10.0.0.33","destination_ip":"198.51.100.99","hostname":"WS-DEV-07","username":"contractor1"}}}'

submit 4 privesc '{"task_type":"privilege_escalation_hunt","input":{"prompt":"Investigate privilege escalation","severity":"critical","siem_event":{"raw_log":"EventID=4672 SubjectUser=svc_backup PrivilegesAssigned=SeDebugPrivilege\nProcess=mimikatz.exe User=svc_backup\nsudo -u root bash","source_ip":"10.0.0.42","destination_ip":"10.0.0.200","hostname":"DC-PRIMARY","username":"svc_backup"}}}'

submit 5 c2 '{"task_type":"c2_communication_hunt","input":{"prompt":"Investigate C2 beaconing","severity":"high","siem_event":{"raw_log":"src_ip=10.0.0.22 dst_ip=185.220.101.42 dst_port=443 bytes_out=256 Process=svchost.exe\nDNS query=c2beacon.evil.io type=A src_ip=10.0.0.22","source_ip":"10.0.0.22","destination_ip":"185.220.101.42","hostname":"WS-ACCT-03","username":"mwilson"}}}'

submit 6 brute_force '{"task_type":"brute_force_investigation","input":{"prompt":"Investigate SSH brute force","severity":"high","siem_event":{"raw_log":"Failed password for admin from 10.0.0.99 port 54321 ssh2\nFailed password for admin from 10.0.0.99 port 54322 ssh2\nFailed password for root from 10.0.0.99 port 54323 ssh2\nFailed password for admin from 10.0.0.99 port 54324 ssh2\nAccepted password for admin from 10.0.0.99 port 54326 ssh2","source_ip":"10.0.0.99","destination_ip":"10.0.0.1","hostname":"SSH-BASTION-01","username":"admin"}}}'

submit 7 insider '{"task_type":"insider_threat_detection","input":{"prompt":"Investigate insider threat","severity":"high","siem_event":{"raw_log":"login time=23:45 user=rthompson src_ip=10.0.0.88\nFileAccess count=847 path=Finance user=rthompson\nUSB EventID=6416 DeviceName=SanDisk user=rthompson\nEmailRule action=forward to=rthompson@gmail.com user=rthompson","source_ip":"10.0.0.88","destination_ip":"10.0.0.1","hostname":"HR-PC-04","username":"rthompson"}}}'

submit 8 lateral '{"task_type":"lateral_movement_detection","input":{"prompt":"Investigate lateral movement","severity":"critical","siem_event":{"raw_log":"EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY.corp.local NTLM_hash=aad3b435b51404eeaad3b435b51404ee\nProcess=mimikatz.exe CommandLine=sekurlsa::pth\nEventID=4648 TargetHost=FILE-SERVER-01.corp.local","source_ip":"10.0.0.50","destination_ip":"10.0.0.200","hostname":"WS-ADMIN-01","username":"svc_backup"}}}'

submit 9 beaconing '{"task_type":"network_beaconing","input":{"prompt":"Investigate network beaconing","severity":"high","siem_event":{"raw_log":"10:00:00 src_ip=10.0.0.15 dst_ip=198.51.100.42 dst_port=443 bytes_out=256 Process=svchost.exe\n10:05:00 src_ip=10.0.0.15 dst_ip=198.51.100.42 dst_port=443 bytes_out=256\n10:10:01 src_ip=10.0.0.15 dst_ip=198.51.100.42 dst_port=443 bytes_out=256\n10:15:00 src_ip=10.0.0.15 dst_ip=198.51.100.42 dst_port=443 bytes_out=256\nDNS query=encoded.c2.evil.com type=TXT src_ip=10.0.0.15","source_ip":"10.0.0.15","destination_ip":"198.51.100.42","hostname":"WS-SALES-02","username":"jturner"}}}'

submit 10 cloud '{"task_type":"cloud_infrastructure_attack","input":{"prompt":"Investigate cloud attack","severity":"critical","siem_event":{"raw_log":"CloudTrail: ConsoleLogin user=arn:aws:iam::123456789:user/admin src_ip=203.0.113.77 MFA=false\nCloudTrail: CreateAccessKey user=admin\nCloudTrail: StopLogging trailName=main-audit\nCloudTrail: RunInstances instanceType=p3.8xlarge count=10\nCloudTrail: GetSecretValue secretId=prod/db/creds","source_ip":"203.0.113.77","destination_ip":"10.0.0.1","hostname":"AWS-CLOUDTRAIL","username":"admin"}}}'

submit 11 supply_chain '{"task_type":"supply_chain_compromise","input":{"prompt":"Investigate supply chain compromise","severity":"critical","siem_event":{"raw_log":"FileIntegrity: HASH_MISMATCH file=update.dll expected=a1b2c3d4e5f6 actual=9f8e7d6c5b4a\nProcess=TrustedApp.exe dst_ip=185.220.101.55 bytes_out=10485760\nDigitalSignature: INVALID file=update.dll\nnpm audit: solarwinds-orion-sdk vulnerability","source_ip":"10.0.0.30","destination_ip":"185.220.101.55","hostname":"BUILD-SERVER-01","username":"ci_pipeline"}}}'

echo ""
echo "=== All 11 submitted. Polling... ==="
sleep 5

NAMES=("phishing" "ransomware" "data_exfil" "privesc" "c2" "brute_force" "insider" "lateral" "beaconing" "cloud" "supply_chain")

# Refresh token for polling
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')

for attempt in $(seq 1 20); do
  ALL_DONE=true
  IDX=0
  while IFS= read -r TID; do
    NAME=${NAMES[$IDX]}
    R=$(curl -s "http://localhost:8090/api/v1/tasks/$TID" -H "Authorization: Bearer $TOKEN")
    STATUS=$(echo "$R" | sed 's/.*"status":"\([^"]*\)".*/\1/')
    if [ "$STATUS" = "pending" ] || [ "$STATUS" = "executing" ]; then
      ALL_DONE=false
    fi
    IDX=$((IDX + 1))
  done < /tmp/hydra_11_ids.txt

  if [ "$ALL_DONE" = true ]; then
    break
  fi

  echo "  Attempt $attempt: some still running..."

  # Re-auth every 5 polls
  if [ $((attempt % 5)) -eq 0 ]; then
    TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@test.local","password":"TestPass2026"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')
  fi

  sleep 15
done

echo ""
echo "=== RESULTS TABLE ==="
echo "# | Template | Status | Risk | Findings | IOCs | Verdict | Time"
echo "--|----------|--------|------|----------|------|---------|-----"

IDX=0
while IFS= read -r TID; do
  NAME=${NAMES[$IDX]}
  IDX=$((IDX + 1))
  R=$(curl -s "http://localhost:8090/api/v1/tasks/$TID" -H "Authorization: Bearer $TOKEN")
  STATUS=$(echo "$R" | sed 's/.*"status":"\([^"]*\)".*/\1/')
  RISK=$(echo "$R" | sed -n 's/.*"risk_score":\([0-9]*\).*/\1/p' | head -1)
  VERDICT=$(echo "$R" | sed -n 's/.*"verdict":"\([^"]*\)".*/\1/p' | head -1)
  EXEC_MS=$(echo "$R" | sed -n 's/.*"execution_ms":\([0-9]*\).*/\1/p' | head -1)

  # Count findings and IOCs
  FINDING_COUNT=$(echo "$R" | grep -o '"title"' | wc -l)
  IOC_COUNT=$(echo "$R" | grep -o '"type":"ip\|"type":"domain\|"type":"hash\|"type":"email\|"type":"username' | wc -l)

  TIME_S=$((${EXEC_MS:-0} / 1000))
  echo "$IDX | $NAME | $STATUS | ${RISK:-0} | $FINDING_COUNT | $IOC_COUNT | ${VERDICT:-n/a} | ${TIME_S}s"
done < /tmp/hydra_11_ids.txt
