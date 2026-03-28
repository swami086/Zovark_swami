# ZOVARK SIEM Integration Guide

## Overview

ZOVARK accepts security alerts via REST API webhook. When a SIEM rule fires, it sends the alert to ZOVARK, which automatically investigates it through the V2 pipeline (Ingest → Analyze → Execute → Assess → Store) and produces a structured verdict.

## Endpoint

```
POST /api/v1/tasks
Content-Type: application/json
Authorization: Bearer <JWT_TOKEN>
```

## Authentication

### Option 1: JWT Token (recommended for testing)
```bash
# Get a token
TOKEN=$(curl -s -X POST https://zovark.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"siem-service@yourdomain.com","password":"<SERVICE_PASSWORD>"}' | jq -r '.token')
```

### Option 2: API Key (recommended for production)
```
Authorization: Bearer <API_KEY>
```
API keys can be generated in the ZOVARK admin panel under Settings → API Keys.

## Request Schema

```json
{
  "task_type": "brute_force",
  "input": {
    "prompt": "Investigate SSH brute force from 10.0.0.99",
    "severity": "high",
    "siem_event": {
      "title": "SSH Brute Force Attack",
      "source_ip": "10.0.0.99",
      "destination_ip": "10.0.0.5",
      "hostname": "WEB-SERVER-01",
      "username": "admin",
      "rule_name": "SSH_Brute_Force_Threshold",
      "raw_log": "Failed password for admin from 10.0.0.99 port 54321 ssh2\nFailed password for admin from 10.0.0.99 port 54322 ssh2"
    }
  }
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `task_type` | string | Yes | Investigation type (see supported types below) |
| `input.prompt` | string | Yes | Human-readable description of what to investigate |
| `input.severity` | string | Yes | `critical`, `high`, `medium`, or `low` |
| `input.siem_event.title` | string | Yes | Alert title from SIEM rule |
| `input.siem_event.source_ip` | string | Yes | Source IP address |
| `input.siem_event.destination_ip` | string | No | Destination IP address |
| `input.siem_event.hostname` | string | No | Affected hostname |
| `input.siem_event.username` | string | No | Affected username |
| `input.siem_event.rule_name` | string | No | SIEM rule that fired |
| `input.siem_event.raw_log` | string | Yes | Raw log data to analyze |

### Supported Task Types

| Task Type | Description |
|-----------|-------------|
| `brute_force` | SSH/RDP/credential brute force attacks |
| `phishing` | Phishing emails and credential harvesting |
| `c2_communication_hunt` | Command and control beacon detection |
| `lateral_movement` | Pass-the-hash, WMI, PsExec lateral movement |
| `ransomware` | Ransomware indicators (encryption, shadow copy deletion) |
| `data_exfiltration` | Large data transfers, DNS tunneling |
| `privilege_escalation` | Token theft, kernel exploits, UAC bypass |
| `insider_threat` | Unusual access patterns, mass downloads |
| `network_beaconing` | Periodic DNS/HTTP beaconing patterns |
| `supply_chain_compromise` | Package tampering, dependency confusion |
| `cloud_infrastructure` | Cloud misconfiguration, IAM issues |

## Response Schema

### Submission Response
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending"
}
```

### Poll for Results
```
GET /api/v1/tasks/<task_id>
Authorization: Bearer <JWT_TOKEN>
```

### Completed Investigation
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "output": {
    "verdict": "true_positive",
    "risk_score": 85,
    "findings": [
      {"title": "SSH Brute Force Confirmed", "details": "47 failed attempts followed by successful login"}
    ],
    "iocs": [
      {"type": "ipv4", "value": "10.0.0.99", "confidence": "high"},
      {"type": "username", "value": "admin", "confidence": "high"}
    ],
    "recommendations": [
      "Block source IP 10.0.0.99",
      "Reset credentials for user admin",
      "Enable MFA on SSH access"
    ],
    "summary": "SSH brute force attack detected from 10.0.0.99 with 47 failed attempts followed by successful authentication."
  }
}
```

## SIEM Configuration Examples

### Splunk

Configure a webhook alert action:

1. Go to **Settings → Alert Actions → Add New**
2. Set the webhook URL:
   ```
   https://zovark.yourdomain.com/api/v1/tasks
   ```
3. Create a saved search with webhook action:
   ```spl
   index=auth sourcetype=sshd "Failed password"
   | stats count by src_ip, dest_ip, user
   | where count > 10
   ```
4. In the webhook configuration, set the payload template:
   ```json
   {
     "task_type": "brute_force",
     "input": {
       "prompt": "Investigate SSH brute force from $result.src_ip$",
       "severity": "high",
       "siem_event": {
         "title": "SSH Brute Force (Splunk Alert)",
         "source_ip": "$result.src_ip$",
         "destination_ip": "$result.dest_ip$",
         "hostname": "$result.dest_ip$",
         "username": "$result.user$",
         "rule_name": "splunk_ssh_brute_force",
         "raw_log": "$result._raw$"
       }
     }
   }
   ```

### Elastic / Kibana Watcher

```json
{
  "trigger": {
    "schedule": { "interval": "5m" }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["filebeat-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                { "match": { "event.action": "ssh_login" }},
                { "match": { "event.outcome": "failure" }}
              ],
              "filter": [{ "range": { "@timestamp": { "gte": "now-5m" }}}]
            }
          },
          "aggs": {
            "by_source": {
              "terms": { "field": "source.ip", "min_doc_count": 10 }
            }
          }
        }
      }
    }
  },
  "actions": {
    "zovark_webhook": {
      "webhook": {
        "method": "POST",
        "url": "https://zovark.yourdomain.com/api/v1/tasks",
        "headers": {
          "Content-Type": "application/json",
          "Authorization": "Bearer {{ctx.metadata.zovark_api_key}}"
        },
        "body": "{\"task_type\":\"brute_force\",\"input\":{\"prompt\":\"Investigate SSH brute force\",\"severity\":\"high\",\"siem_event\":{\"title\":\"SSH Brute Force (Elastic)\",\"source_ip\":\"{{ctx.payload.aggregations.by_source.buckets.0.key}}\",\"rule_name\":\"elastic_ssh_brute_force\",\"raw_log\":\"{{ctx.payload.hits.total.value}} failed SSH attempts in 5 minutes\"}}}"
      }
    }
  }
}
```

### Microsoft Sentinel (Logic App)

1. Create a new Logic App with **Microsoft Sentinel alert trigger**
2. Add an HTTP action:
   - Method: `POST`
   - URI: `https://zovark.yourdomain.com/api/v1/tasks`
   - Headers:
     - `Content-Type`: `application/json`
     - `Authorization`: `Bearer <API_KEY>`
   - Body:
   ```json
   {
     "task_type": "brute_force",
     "input": {
       "prompt": "@{triggerBody()?['AlertDisplayName']}",
       "severity": "@{triggerBody()?['AlertSeverity']}",
       "siem_event": {
         "title": "@{triggerBody()?['AlertDisplayName']}",
         "source_ip": "@{triggerBody()?['Entities']?[0]?['Address']}",
         "hostname": "@{triggerBody()?['Entities']?[1]?['HostName']}",
         "username": "@{triggerBody()?['Entities']?[2]?['Name']}",
         "rule_name": "@{triggerBody()?['AlertType']}",
         "raw_log": "@{triggerBody()?['Description']}"
       }
     }
   }
   ```

### Generic curl Example

```bash
curl -X POST https://zovark.yourdomain.com/api/v1/tasks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ZOVARK_TOKEN" \
  -d '{
    "task_type": "brute_force",
    "input": {
      "prompt": "Investigate brute force from 10.0.0.99",
      "severity": "high",
      "siem_event": {
        "title": "SSH Brute Force",
        "source_ip": "10.0.0.99",
        "destination_ip": "10.0.0.5",
        "hostname": "WEB-SERVER-01",
        "username": "admin",
        "rule_name": "My_SIEM_Rule",
        "raw_log": "Failed password for admin from 10.0.0.99"
      }
    }
  }'
```

## Field Mapping Reference

| SIEM Field | ZOVARK Field | Notes |
|------------|-------------|-------|
| Source IP / src_ip | `siem_event.source_ip` | IPv4 or IPv6 |
| Destination IP / dst_ip | `siem_event.destination_ip` | Target system |
| Hostname / host | `siem_event.hostname` | Affected endpoint |
| Username / user | `siem_event.username` | Account involved |
| Alert Name / rule | `siem_event.rule_name` | SIEM rule name |
| Alert Title | `siem_event.title` | Human-readable title |
| Raw Event / _raw | `siem_event.raw_log` | Full log entry |
| Severity | `input.severity` | Map to: critical/high/medium/low |

## Rate Limits

| Tier | Rate Limit | Burst |
|------|-----------|-------|
| Default | 60 requests/minute | 10 concurrent |
| Enterprise | 300 requests/minute | 50 concurrent |

Alerts that exceed the rate limit receive HTTP 429. Implement exponential backoff in your SIEM webhook configuration.

## Error Handling

| HTTP Code | Meaning | Action |
|-----------|---------|--------|
| 200 | Alert accepted | Poll for results |
| 400 | Invalid payload | Check request schema |
| 401 | Authentication failed | Refresh JWT token |
| 429 | Rate limited | Back off and retry |
| 500 | Server error | Retry after 30s |

## Deduplication

ZOVARK automatically deduplicates identical alerts within a configurable window (default: 1 hour). Duplicate submissions return:
```json
{
  "task_id": "original-task-id",
  "status": "deduplicated"
}
```
