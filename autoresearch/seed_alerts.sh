#!/usr/bin/env bash
set -euo pipefail
export MSYS_NO_PATHCONV=1

echo "═══════════════════════════════════════"
echo "  SEEDING FRESH INVESTIGATIONS"
echo "═══════════════════════════════════════"

# 1. Get auth token
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.local","password":"TestPass2026"}' \
  | sed 's/.*"token":"\([^"]*\)".*/\1/')

if [ ${#TOKEN} -lt 50 ]; then
  echo "ERROR: Failed to get auth token"
  exit 1
fi
echo "✓ Auth token acquired (${#TOKEN} chars)"

# 2. Alert definitions: type|severity|raw_log
ALERTS=(
  'brute_force|high|sshd[12345]: Failed password for root from 198.51.100.77 port 44221 ssh2. sshd[12346]: Failed password for root from 198.51.100.77 port 44222 ssh2. 847 failed attempts in 300 seconds from single source IP'
  'kerberoasting|critical|EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01.corp.local:1433 TargetUserName=svc_backup ClientAddress=10.0.0.55 TicketOptions=0x40810000. 15 RC4 TGS requests in 30 seconds from single source'
  'phishing_investigation|high|From: security-update@micr0soft-verify.com To: john.doe@company.com Subject: Urgent Password Reset Required URL: https://micr0soft-verify.com/reset?token=abc123 X-Mailer: PHPMailer 5.2.28 Received: from mail.suspicious-domain.ru'
  'ransomware_triage|critical|vssadmin.exe delete shadows /all /quiet. wmic shadowcopy delete. bcdedit /set recoveryenabled No. notepad.exe README_RESTORE.txt. 1847 files renamed to .encrypted extension in 120 seconds'
  'c2_communication_hunt|high|Outbound connection to 185.220.101.45:443 every 60.2s jitter 0.3s. DNS query: x7kf9.evil-domain.com high entropy subdomain. HTTPS POST 256 bytes every 60s for 4 hours. User-Agent: Mozilla/5.0 compatible MSIE 10.0'
  'lateral_movement_detection|high|EventID=4648 SubjectUserName=admin_svc TargetServerName=DC01 ProcessName=PsExec.exe. EventID=7045 ServiceName=PSEXESVC. New service installed on DC01 from workstation WS055. Admin share DC01 ADMIN$ accessed'
  'data_exfiltration_detection|high|POST https://drive.google.com/upload 2.3GB at 02:30 AM. User jane.smith uploaded 847 files to personal Google Drive. Files include customer_database_export.csv financial_Q4_2025.xlsx. Normal volume under 50MB per day'
  'lolbin_abuse|high|certutil used for file download from external host 203.0.113.50 to Users-Public directory. certutil decode operation on encoded.txt producing payload.dll. mshta loading remote HTA from 203.0.113.50. Process tree: explorer cmd certutil'
  'password_change|low|EventID=4724 TargetUserName=user1 SubjectUserName=user1 SubjectDomainName=CORP routine password change completed successfully at 2026-03-31T14:00:00Z'
  'benign_system_event|low|EventID=7036 The Windows Update service entered the running state. Routine scheduled maintenance completed. No errors detected. System uptime 45 days'
)

echo ""
echo "Submitting ${#ALERTS[@]} alerts..."

for entry in "${ALERTS[@]}"; do
  IFS='|' read -r task_type severity raw_log <<< "$entry"

  response=$(curl -s -X POST http://localhost:8090/api/v1/tasks \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"task_type\":\"${task_type}\",\"input\":{\"prompt\":\"${task_type} investigation\",\"severity\":\"${severity}\",\"siem_event\":{\"title\":\"${task_type}\",\"source_ip\":\"10.0.0.42\",\"username\":\"testuser\",\"rule_name\":\"${task_type}\",\"raw_log\":\"${raw_log}\"}}}")

  task_id=$(echo "$response" | sed 's/.*"task_id":"\([^"]*\)".*/\1/')
  echo "  ✓ ${task_type} -> ${task_id}"
done

echo ""
echo "✓ All ${#ALERTS[@]} alerts submitted"
echo "Waiting 5 minutes for pipeline completion..."
sleep 300

# 3. Print completion count
echo ""
echo "═══════════════════════════════════════"
echo "  RESULTS"
echo "═══════════════════════════════════════"
docker compose exec -T postgres psql -U zovark -d zovark -c "
SELECT
  status,
  COUNT(*) as count
FROM agent_tasks
GROUP BY status
ORDER BY status;
"
docker compose exec -T postgres psql -U zovark -d zovark -c "
SELECT
  task_type,
  status,
  output->>'risk_score' as risk,
  output->>'verdict' as verdict,
  execution_ms
FROM agent_tasks
ORDER BY created_at;
"

COMPLETED=$(docker compose exec -T postgres psql -U zovark -d zovark -t -c "SELECT COUNT(*) FROM agent_tasks WHERE status='completed'")
TOTAL=$(docker compose exec -T postgres psql -U zovark -d zovark -t -c "SELECT COUNT(*) FROM agent_tasks")
echo ""
echo "✓ ${COMPLETED// /}/${TOTAL// /} investigations completed"
