#!/bin/sh

apk add --no-cache curl jq > /dev/null 2>&1

echo "1. Getting Token..."
curl -v -s -X POST http://hydra-api:8090/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"demouser2@testcorp.com","password":"password123"}' > /tmp/login.json 2> /tmp/curl_err.txt

TOKEN=$(cat /tmp/login.json | jq -r '.token // empty')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "Failed to get token!"
    cat /tmp/login.json
    cat /tmp/curl_err.txt
    exit 1
fi

echo "Token acquired."

echo "\n2. Test playbook list:"
PLAYBOOKS=$(curl -s http://hydra-api:8090/api/v1/playbooks -H "Authorization: Bearer $TOKEN")
echo $PLAYBOOKS | jq

DDOS_ID=$(echo $PLAYBOOKS | jq -r '.[] | select(.name == "DDoS Response") | .id')
echo "\nDDoS Playbook ID: $DDOS_ID"

echo "\n3. Test creating custom playbook:"
curl -s -X POST http://hydra-api:8090/api/v1/playbooks \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"AWS Credential Leak","description":"Triage IAM credential leaks","icon":"☁️","task_type":"incident_response","steps":["Analyze CloudTrail logs for compromised key usage","Identify new IAM users or EC2 instances created by compromised key"]}' | jq

echo "\n\n4. Test launching investigation from playbook:"
TASK_RESP=$(curl -s -X POST http://hydra-api:8090/api/v1/tasks \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"playbook_id\":\"$DDOS_ID\",\"prompt\":\"Analyze logs for DDoS patterns\"}")

echo $TASK_RESP | jq
TASK_ID=$(echo $TASK_RESP | jq -r '.task_id')

echo "\nWaiting 60 seconds for investigation steps to execute deterministically..."
sleep 60
echo "Done."
