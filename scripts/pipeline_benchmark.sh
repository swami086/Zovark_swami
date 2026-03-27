#!/bin/bash
# Pipeline benchmark: submit 7 investigations through Temporal pipeline
# Each waits for completion before submitting next (single-slot llama-server)
set -euo pipefail

API="http://localhost:8090"

# Login
TOKEN=$(curl -s -X POST "$API/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${ZOVARC_TEST_EMAIL:-admin@test.local}\",\"password\":\"${ZOVARC_TEST_PASSWORD:-TestPass2026}\"}" \
  | sed 's/.*"token":"\([^"]*\)".*/\1/')
echo "Token: ${TOKEN:0:20}..."

submit_and_wait() {
  local NAME="$1"
  local NUM="$2"
  local PAYLOAD="$3"

  echo ""
  echo "[$NUM/7] $NAME — submitting..."
  RESP=$(curl -s -X POST "$API/api/v1/tasks" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")
  TASK_ID=$(echo "$RESP" | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
  echo "  Task: $TASK_ID"

  for i in $(seq 1 15); do
    sleep 60
    STATUS=$(curl -s "$API/api/v1/tasks/$TASK_ID" \
      -H "Authorization: Bearer $TOKEN" | grep -o '"status":"[^"]*"' | head -1 | sed 's/"status":"//;s/"//')
    echo "  [$i min] $STATUS"
    if [ "$STATUS" != "pending" ] && [ "$STATUS" != "executing" ]; then
      break
    fi
  done

  echo "  RESULT: $NAME = $STATUS (task $TASK_ID)"
}

echo "=== PIPELINE BENCHMARK START ==="
echo "Model: $(curl -s http://localhost:11434/v1/models | grep -o '"name":"[^"]*"' | head -1)"
echo "Time: $(date)"
echo ""

# 1. SSH Brute Force
submit_and_wait "SSH Brute Force" 1 '{
  "task_type":"brute_force",
  "input":{
    "prompt":"Analyze SSH brute force attack pattern",
    "severity":"high",
    "siem_event":{
      "title":"SSH Brute Force Attack",
      "source_ip":"10.0.0.99",
      "destination_ip":"10.0.0.5",
      "hostname":"WEB-SERVER-01",
      "username":"admin",
      "rule_name":"SSH_Brute_Force",
      "raw_log":"Failed password for admin from 10.0.0.99 port 54321 ssh2\nFailed password for admin from 10.0.0.99 port 54322 ssh2\nFailed password for root from 10.0.0.99 port 54323 ssh2\nAccepted password for admin from 10.0.0.99 port 54324 ssh2"
    }
  }
}'

# 2. Lateral Movement PtH
submit_and_wait "Lateral Movement PtH" 2 '{
  "task_type":"lateral_movement",
  "input":{
    "prompt":"Investigate NTLM pass-the-hash lateral movement",
    "severity":"critical",
    "siem_event":{
      "title":"Pass the Hash Lateral Movement",
      "source_ip":"10.0.0.50",
      "destination_ip":"10.0.0.200",
      "hostname":"WS-FINANCE-03",
      "username":"svc_backup",
      "rule_name":"PtH_Detected",
      "raw_log":"EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY.corp.local TargetIP=10.0.0.200 User=svc_backup NTLM_hash=aad3b435b51404eeaad3b435b51404ee Process=svchost.exe ParentProcess=mimikatz.exe CommandLine=sekurlsa::pth /user:svc_backup /domain:corp.local"
    }
  }
}'

# 3. C2 Beaconing
submit_and_wait "C2 Beaconing" 3 '{
  "task_type":"c2_communication_hunt",
  "input":{
    "prompt":"Investigate C2 beacon communication pattern",
    "severity":"high",
    "siem_event":{
      "title":"C2 Beacon Detected",
      "source_ip":"10.0.0.15",
      "destination_ip":"185.220.101.42",
      "hostname":"WORKSTATION-07",
      "username":"jsmith",
      "rule_name":"C2_Beacon",
      "raw_log":"DNS query: evil-c2.xyz from 10.0.0.15\nHTTP POST http://185.220.101.42/beacon interval=60s size=256b\nUserAgent=Mozilla/5.0 (compatible; bot)"
    }
  }
}'

# 4. Ransomware
submit_and_wait "Ransomware" 4 '{
  "task_type":"ransomware",
  "input":{
    "prompt":"Investigate ransomware file encryption activity",
    "severity":"critical",
    "siem_event":{
      "title":"Ransomware File Encryption",
      "source_ip":"10.0.0.75",
      "destination_ip":"10.0.0.100",
      "hostname":"FILE-SERVER-01",
      "username":"bob.jones",
      "rule_name":"Ransomware_Detected",
      "raw_log":"FileRename: documents.docx -> documents.docx.locked\nFileRename: report.xlsx -> report.xlsx.locked\nProcess=cryptor.exe MD5=d41d8cd98f00b204e9800998ecf8427e\nRegistryWrite: HKLM\\Software\\Ransom\\key=INFECTED"
    }
  }
}'

# 5. Phishing
submit_and_wait "Phishing" 5 '{
  "task_type":"phishing",
  "input":{
    "prompt":"Investigate phishing email with malicious attachment",
    "severity":"high",
    "siem_event":{
      "title":"Phishing Email Detected",
      "source_ip":"192.168.1.50",
      "destination_ip":"192.168.1.1",
      "hostname":"MAIL-SERVER",
      "username":"alice@corp.local",
      "rule_name":"Phishing_Detected",
      "raw_log":"From: attacker@evil.com To: alice@corp.local Subject: Urgent Invoice\nURL: http://phish.evil.com/steal-creds\nAttachment: invoice.exe MD5=5d41402abc4b2a76b9719d911017c592"
    }
  }
}'

# 6. Data Exfiltration
submit_and_wait "Data Exfiltration" 6 '{
  "task_type":"data_exfiltration",
  "input":{
    "prompt":"Investigate large outbound data transfer",
    "severity":"high",
    "siem_event":{
      "title":"Data Exfiltration Large Transfer",
      "source_ip":"10.0.0.30",
      "destination_ip":"203.0.113.99",
      "hostname":"DB-SERVER-01",
      "username":"db_admin",
      "rule_name":"Data_Exfil",
      "raw_log":"Outbound transfer: 10.0.0.30 -> 203.0.113.99 size=4.2GB protocol=HTTPS\nProcess=rclone.exe args=copy /data s3://external-bucket\nUser=db_admin elevated=true"
    }
  }
}'

# 7. Privilege Escalation
submit_and_wait "Privilege Escalation" 7 '{
  "task_type":"privilege_escalation",
  "input":{
    "prompt":"Investigate privilege escalation via token theft",
    "severity":"critical",
    "siem_event":{
      "title":"Privilege Escalation Detected",
      "source_ip":"10.0.0.22",
      "destination_ip":"10.0.0.1",
      "hostname":"WORKSTATION-12",
      "username":"temp_user",
      "rule_name":"PrivEsc_Detected",
      "raw_log":"EventID=4672 PrivilegesAssigned=SeDebugPrivilege User=temp_user\nProcess=psexec.exe -s cmd.exe\nEventID=4624 LogonType=2 User=SYSTEM Source=10.0.0.22\nNew service created: malware_svc path=C:\\Windows\\Temp\\evil.exe"
    }
  }
}'

echo ""
echo "=== PIPELINE BENCHMARK COMPLETE ==="
echo "Time: $(date)"
echo ""
echo "Retry count:"
docker compose logs worker 2>&1 | grep -c "CODE_RETRY" || echo "0"
