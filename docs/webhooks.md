# ZOVARK Webhook Event Catalog

ZOVARK supports outbound webhooks to notify external systems of platform events. Webhooks are delivered as HTTP POST requests with JSON payloads, authenticated via HMAC-SHA256 signatures.

## Table of Contents

- [Event Types](#event-types)
- [Payload Format](#payload-format)
- [Event Schemas](#event-schemas)
- [Setup Instructions](#setup-instructions)
- [Security](#security)
- [Retry Policy](#retry-policy)
- [API Reference](#api-reference)

---

## Event Types

| Event Type                | Description                                      | Trigger                          |
|---------------------------|--------------------------------------------------|----------------------------------|
| `investigation_completed` | An investigation has finished (pass or fail)     | Task status -> completed/failed  |
| `alert_received`          | A new SIEM alert was ingested                    | POST /api/v1/webhooks/:id/alert  |
| `approval_needed`         | An investigation step requires human approval    | High-risk action detected        |
| `response_executed`       | A SOAR response action was executed              | Playbook action completed        |

---

## Payload Format

All webhook deliveries use a standard envelope format:

```json
{
  "event_type": "investigation_completed",
  "tenant_id": "zovark-dev",
  "timestamp": "2026-03-10T14:30:00Z",
  "data": {
    // Event-specific payload (see below)
  }
}
```

### HTTP Headers

| Header                | Description                                      |
|-----------------------|--------------------------------------------------|
| `Content-Type`        | `application/json`                               |
| `User-Agent`          | `ZOVARK-Webhook/1.0`                              |
| `X-Webhook-Signature` | HMAC-SHA256 hex digest of the request body       |

---

## Event Schemas

### `investigation_completed`

Fired when an investigation task reaches a terminal state (`completed` or `failed`).

```json
{
  "event_type": "investigation_completed",
  "tenant_id": "zovark-dev",
  "timestamp": "2026-03-10T14:30:00Z",
  "data": {
    "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "status": "completed",
    "task_type": "log_analysis",
    "verdict": "suspicious",
    "risk_score": 75,
    "severity": "high",
    "execution_ms": 12500,
    "step_count": 3,
    "entities_found": 8,
    "mitre_techniques": ["T1110.001", "T1078"],
    "summary": "Brute force attack detected from 192.168.1.100 targeting SSH service"
  }
}
```

### `alert_received`

Fired when a new SIEM alert is ingested via the webhook alert endpoint.

```json
{
  "event_type": "alert_received",
  "tenant_id": "zovark-dev",
  "timestamp": "2026-03-10T14:25:00Z",
  "data": {
    "alert_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
    "title": "Suspicious SSH Activity Detected",
    "severity": "high",
    "source": "crowdstrike",
    "source_ref": "CS-ALERT-2026-001",
    "indicators": {
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.5",
      "dst_port": 22,
      "username": "root"
    }
  }
}
```

### `approval_needed`

Fired when an investigation step requires human approval before proceeding (e.g., high-risk automated response).

```json
{
  "event_type": "approval_needed",
  "tenant_id": "zovark-dev",
  "timestamp": "2026-03-10T14:28:00Z",
  "data": {
    "approval_id": "c3d4e5f6-a7b8-9012-cdef-345678901234",
    "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "step_number": 2,
    "risk_level": "critical",
    "action_summary": "Block IP 192.168.1.100 at perimeter firewall",
    "generated_code": "firewall.block_ip('192.168.1.100', duration='24h')",
    "requested_at": "2026-03-10T14:28:00Z"
  }
}
```

### `response_executed`

Fired when a SOAR response playbook action is executed.

```json
{
  "event_type": "response_executed",
  "tenant_id": "zovark-dev",
  "timestamp": "2026-03-10T14:32:00Z",
  "data": {
    "execution_id": "d4e5f6a7-b8c9-0123-def4-567890123456",
    "playbook_id": "pb-firewall-block",
    "playbook_name": "Firewall Block",
    "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "action_type": "firewall_block",
    "status": "completed",
    "target": "192.168.1.100",
    "result": {
      "blocked": true,
      "rule_id": "FW-RULE-2026-0042"
    }
  }
}
```

---

## Setup Instructions

### 1. Create a Webhook Endpoint

Register a webhook endpoint via the API (requires admin role):

```bash
curl -X POST http://localhost:8090/api/v1/webhooks/endpoints \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slack Notifications",
    "url": "https://hooks.slack.com/services/xxx/yyy/zzz",
    "event_types": ["investigation_completed", "approval_needed"]
  }'
```

Response:
```json
{
  "id": "ep-uuid",
  "name": "Slack Notifications",
  "url": "https://hooks.slack.com/services/xxx/yyy/zzz",
  "secret": "a1b2c3d4e5f6...",
  "event_types": ["investigation_completed", "approval_needed"]
}
```

**Important:** Save the `secret` value. It is only returned once and is used to verify webhook signatures.

### 2. Verify Signatures

All webhook deliveries include an `X-Webhook-Signature` header containing an HMAC-SHA256 hex digest of the request body, using the endpoint secret as the key.

Python verification example:

```python
import hmac
import hashlib

def verify_webhook(body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Node.js verification example:

```javascript
const crypto = require('crypto');

function verifyWebhook(body, signature, secret) {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signature),
  );
}
```

### 3. Manage Endpoints

```bash
# List all endpoints
curl http://localhost:8090/api/v1/webhooks/endpoints \
  -H "Authorization: Bearer $TOKEN"

# Update an endpoint
curl -X PUT http://localhost:8090/api/v1/webhooks/endpoints/$ENDPOINT_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event_types": ["investigation_completed"]}'

# Deactivate an endpoint
curl -X DELETE http://localhost:8090/api/v1/webhooks/endpoints/$ENDPOINT_ID \
  -H "Authorization: Bearer $TOKEN"

# View delivery history
curl http://localhost:8090/api/v1/webhooks/deliveries \
  -H "Authorization: Bearer $TOKEN"
```

---

## Security

| Feature              | Implementation                                    |
|----------------------|---------------------------------------------------|
| Authentication       | HMAC-SHA256 signature on every delivery           |
| Secret Generation    | 32 bytes of cryptographic randomness (hex-encoded)|
| Transport            | HTTPS recommended for production endpoints        |
| Timeout              | 10-second timeout per delivery attempt            |
| Signature Header     | `X-Webhook-Signature`                             |

### Best Practices

1. Always verify the `X-Webhook-Signature` before processing payloads
2. Use HTTPS endpoints in production
3. Respond with 2xx status within 10 seconds to avoid retries
4. Store the webhook secret securely (e.g., environment variable or vault)
5. Implement idempotency — the same event may be delivered more than once

---

## Retry Policy

ZOVARK uses exponential backoff for failed webhook deliveries:

| Attempt | Delay   | Total Elapsed |
|---------|---------|---------------|
| 1       | 0s      | 0s            |
| 2       | 1s      | 1s            |
| 3       | 4s      | 5s            |

- **Maximum attempts:** 3
- **Backoff formula:** `attempt^2` seconds
- **Success criteria:** HTTP 2xx response within 10 seconds
- **Final status:** After 3 failed attempts, delivery is marked as `failed`

### Delivery Statuses

| Status      | Description                                |
|-------------|--------------------------------------------|
| `pending`   | Delivery created, not yet attempted        |
| `delivered` | Successfully delivered (2xx response)      |
| `failed`    | All retry attempts exhausted               |

---

## API Reference

### Endpoints

| Method | Path                                | Auth   | Description                    |
|--------|-------------------------------------|--------|--------------------------------|
| GET    | /api/v1/webhooks/endpoints          | JWT    | List webhook endpoints         |
| POST   | /api/v1/webhooks/endpoints          | Admin  | Create webhook endpoint        |
| PUT    | /api/v1/webhooks/endpoints/:id      | Admin  | Update webhook endpoint        |
| DELETE | /api/v1/webhooks/endpoints/:id      | Admin  | Deactivate webhook endpoint    |
| GET    | /api/v1/webhooks/deliveries         | JWT    | List delivery history          |
| POST   | /api/v1/webhooks/:source_id/alert   | HMAC   | Ingest external alert          |

### Valid Event Types

- `investigation_completed`
- `alert_received`
- `approval_needed`
- `response_executed`

### Database Tables

- `webhook_endpoints` — Registered endpoints with secrets and event filters
- `webhook_deliveries` — Delivery attempt log with status and HTTP response codes
