# HYDRA Sprint 2B — SOAR: Automated Response Playbooks
## Claude Code Prompt

---

You are building Sprint 2B for HYDRA, an AI-powered SOC investigation automation platform. This sprint extends HYDRA from "investigate and report" to "investigate and respond" — adding automated response playbooks powered by Temporal workflows. This transforms HYDRA from a point tool into a platform.

## Context

HYDRA's Temporal workflow engine is already 80% of what a SOAR needs — durable execution, retry logic, approval gates, timeout handling. Sprint 2B adds response actions that execute after an investigation produces a high-confidence finding.

The approval gate infrastructure already exists (approval_requests table, signal-based approval in Temporal). Sprint 2B extends it with response-specific playbooks.

## Deliverables

### 2B-1: Response Action Framework

Create `worker/response/actions.py`:

Define the response action interface and built-in actions:

```python
class ResponseAction:
    """Base class for all response actions."""
    action_type: str           # block_ip, disable_user, isolate_endpoint, etc.
    requires_approval: bool    # True for destructive actions
    rollback_capable: bool     # True if action can be undone
    timeout_seconds: int       # max execution time
    
    async def execute(self, context: dict) -> dict:
        """Execute the response action. Returns result dict."""
        raise NotImplementedError
    
    async def rollback(self, context: dict, execution_result: dict) -> dict:
        """Rollback the action if possible."""
        raise NotImplementedError
    
    async def validate(self, context: dict) -> bool:
        """Pre-flight check: can this action be executed?"""
        raise NotImplementedError
```

Built-in response actions (all simulate/log by default, real integration via webhooks):

1. **BlockIP** — Add IP to firewall blocklist
   - Input: ip_address, duration_hours, reason
   - Approval: required if duration > 24h
   - Rollback: remove from blocklist

2. **DisableUser** — Disable user account
   - Input: user_id, identity_provider, reason
   - Approval: always required
   - Rollback: re-enable account

3. **IsolateEndpoint** — Network-isolate a compromised endpoint
   - Input: hostname, endpoint_id, reason
   - Approval: always required
   - Rollback: remove isolation

4. **RotateCredentials** — Force credential rotation
   - Input: user_id, credential_type
   - Approval: required
   - Rollback: not applicable

5. **CreateTicket** — Create incident ticket in ticketing system
   - Input: title, description, severity, assignee
   - Approval: not required
   - Rollback: close ticket

6. **SendNotification** — Send alert to SOC team
   - Input: channel (email/slack/webhook), message, severity
   - Approval: not required
   - Rollback: not applicable

7. **QuarantineFile** — Move suspicious file to quarantine
   - Input: file_hash, hostname, file_path
   - Approval: required
   - Rollback: restore file

### 2B-2: Response Playbook Schema

Create playbook definitions:

```sql
CREATE TABLE IF NOT EXISTS response_playbooks (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger_conditions JSONB NOT NULL,  -- when to activate
    actions JSONB NOT NULL,             -- ordered list of response actions
    requires_approval BOOLEAN DEFAULT true,
    enabled BOOLEAN DEFAULT true,
    tenant_id UUID REFERENCES tenants(id),  -- NULL = global playbook
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS response_executions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    playbook_id UUID REFERENCES response_playbooks(id),
    investigation_id UUID,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    trigger_data JSONB,          -- what triggered this execution
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN (
        'pending', 'awaiting_approval', 'executing', 'completed', 
        'failed', 'rolled_back', 'cancelled'
    )),
    actions_executed JSONB DEFAULT '[]',  -- log of each action + result
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_response_exec_tenant ON response_executions(tenant_id);
CREATE INDEX idx_response_exec_status ON response_executions(status);
CREATE INDEX idx_response_exec_investigation ON response_executions(investigation_id);
```

### 2B-3: Playbook Temporal Workflow

Create `worker/response/workflow.py`:

`ResponsePlaybookWorkflow` — a Temporal workflow that:

1. Receives: investigation_id, playbook_id, trigger_data
2. Checks if playbook requires approval
   - If yes: create approval_request, wait for signal (reuse existing approval gate pattern)
   - Timeout: configurable per playbook (default 4 hours for critical, 24 hours for high)
3. For each action in the playbook (sequential):
   - Validate: call action.validate() — pre-flight check
   - Execute: call action.execute() — perform the action
   - Log: record action + result in response_executions.actions_executed
   - If action fails: stop execution, mark playbook as failed, attempt rollback of completed actions
4. On completion: update response_executions status, send notification
5. On timeout: mark as cancelled, no actions taken

### 2B-4: Webhook Integration Layer

Create `worker/response/webhooks.py`:

Response actions need to communicate with external systems (firewalls, identity providers, EDR tools). In production, these are webhooks:

```python
class WebhookIntegration:
    """Send response actions to external systems via webhook."""
    
    async def send_action(self, 
                          webhook_url: str, 
                          action_type: str, 
                          payload: dict,
                          auth_header: str = None) -> dict:
        """POST action payload to webhook URL."""
```

Store webhook configurations per tenant:
```sql
CREATE TABLE IF NOT EXISTS response_integrations (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    integration_type VARCHAR(50) NOT NULL,  -- firewall, identity, edr, ticketing, notification
    name VARCHAR(255),
    webhook_url TEXT NOT NULL,
    auth_type VARCHAR(20) CHECK (auth_type IN ('none', 'bearer', 'api_key', 'basic')),
    auth_credentials TEXT,    -- encrypted, or reference to secret manager
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 2B-5: Auto-Trigger from Investigation Results

Wire playbook triggering into the investigation workflow:

After investigation completes (in workflows.py, after entity graph pipeline):

1. Check investigation verdict and risk_score
2. Match against playbook trigger_conditions:
   - `{"verdict": "true_positive", "risk_score_gte": 80, "techniques_include": ["T1110"]}` → trigger "Brute Force Response" playbook
   - `{"verdict": "true_positive", "risk_score_gte": 90}` → trigger "Critical Incident Response" playbook
3. Start ResponsePlaybookWorkflow as a child workflow

### 2B-6: Seed Default Playbooks

Create `scripts/seed_playbooks.py`:

Seed 5 default playbooks:

1. **Brute Force Response** (trigger: T1110 + risk >= 70)
   - Block source IP for 24h → Send notification → Create ticket

2. **Ransomware Response** (trigger: ransomware skill + risk >= 80)
   - Isolate endpoint → Disable user → Send critical notification → Create ticket
   - Requires approval

3. **C2 Communication Response** (trigger: T1071 + risk >= 75)
   - Block destination domain → Send notification → Create ticket

4. **Lateral Movement Response** (trigger: T1021 + risk >= 70)
   - Disable compromised user → Send notification → Create ticket
   - Requires approval

5. **Phishing Response** (trigger: phishing skill + risk >= 60)
   - Quarantine email attachment → Send notification → Create ticket

### 2B-7: Response API Endpoints

Add to Go API:

`GET /api/v1/playbooks` — list playbooks for tenant
`POST /api/v1/playbooks` — create custom playbook
`PUT /api/v1/playbooks/{id}` — update playbook
`DELETE /api/v1/playbooks/{id}` — disable playbook

`GET /api/v1/response/executions` — list response executions
`GET /api/v1/response/executions/{id}` — execution details + action log
`POST /api/v1/response/executions/{id}/approve` — approve pending execution
`POST /api/v1/response/executions/{id}/rollback` — rollback completed execution

### 2B-8: Metrics

- `hydra_playbook_triggers_total{playbook, technique}` — counter
- `hydra_playbook_executions_total{playbook, status}` — counter
- `hydra_response_action_duration_seconds{action_type}` — histogram
- `hydra_response_approvals_pending` — gauge
- `hydra_response_rollbacks_total{playbook}` — counter

## Important Constraints

- **All destructive actions require approval by default.** No auto-execute of block/disable/isolate without human confirmation (configurable per playbook, but default is safe).
- Response actions are simulated (log-only) until a webhook integration is configured for the tenant. This allows testing playbooks without real-world impact.
- Rollback must be idempotent — calling rollback twice shouldn't cause errors.
- The ResponsePlaybookWorkflow is a child workflow of the investigation workflow, inheriting tenant context.
- Air-gap compatible: webhook integrations are optional. Core playbook logic works without external connectivity.
- Auth credentials for webhooks should NOT be stored in plaintext — at minimum base64 encode, with a TODO for Vault integration.

## Definition of Done

- [ ] 7 response action types implemented (BlockIP through QuarantineFile)
- [ ] 5 default playbooks seeded
- [ ] Playbook triggers automatically from investigation results
- [ ] Approval gate works: high-risk playbook waits for human approval
- [ ] Rollback works: completed actions can be reversed
- [ ] Response execution log captures every action + result
- [ ] API endpoints for playbook CRUD and execution management
- [ ] Simulated mode: actions log but don't execute without webhook config
- [ ] Git commit: "Sprint 2B: SOAR response playbooks via Temporal workflows"
