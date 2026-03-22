-- Migration 052: Sprint 2B — SOAR Response Playbooks Enhancements
-- Base tables (response_playbooks, response_executions, response_integrations)
-- already exist from migration 009. This adds:
--   - approval_token column to response_executions
--   - error_message column to response_executions
--   - vault_path and credentials_migrated to response_integrations
--   - 5 default seed playbooks

-- Add approval_token for webhook-based approval flows
ALTER TABLE response_executions ADD COLUMN IF NOT EXISTS approval_token VARCHAR(255);
ALTER TABLE response_executions ADD COLUMN IF NOT EXISTS error_message TEXT;

-- Add Vault integration columns to response_integrations
ALTER TABLE response_integrations ADD COLUMN IF NOT EXISTS vault_path TEXT;
ALTER TABLE response_integrations ADD COLUMN IF NOT EXISTS credentials_migrated BOOLEAN DEFAULT false;

-- Index for approval token lookups
CREATE INDEX IF NOT EXISTS idx_response_exec_approval_token
    ON response_executions(approval_token) WHERE approval_token IS NOT NULL;

-- ============================================================
-- Seed 5 default playbooks (global, tenant_id = NULL)
-- ============================================================

-- 1. Brute Force Response (trigger: T1110 + risk >= 70)
INSERT INTO response_playbooks (name, description, trigger_conditions, actions, requires_approval, enabled, tenant_id)
VALUES (
    'Brute Force Response',
    'Automated response to brute force attacks. Blocks source IP, notifies SOC, creates incident ticket.',
    '{"verdict": "true_positive", "risk_score_gte": 70, "techniques_include": ["T1110"]}',
    '[
        {"type": "block_ip", "context": {"ip": "{{attacker_ip}}", "duration_hours": 24, "reason": "Brute force detection"}},
        {"type": "send_notification", "context": {"channel": "security", "message": "Brute force attack detected from {{attacker_ip}}", "severity": "high"}},
        {"type": "create_ticket", "context": {"title": "Brute Force Attack - {{attacker_ip}}", "description": "HYDRA detected brute force activity (T1110). Investigation ID: {{investigation_id}}", "priority": "high"}}
    ]',
    false,
    true,
    NULL
)
ON CONFLICT DO NOTHING;

-- 2. Ransomware Response (trigger: ransomware + risk >= 80)
INSERT INTO response_playbooks (name, description, trigger_conditions, actions, requires_approval, enabled, tenant_id)
VALUES (
    'Ransomware Response',
    'Critical incident response for ransomware. Isolates endpoint, disables user, notifies SOC, creates P1 ticket.',
    '{"verdict": "true_positive", "risk_score_gte": 80, "techniques_include": ["T1486"]}',
    '[
        {"type": "isolate_endpoint", "context": {"hostname": "{{source_host}}", "reason": "Ransomware detection"}},
        {"type": "disable_user", "context": {"username": "{{attacker_username}}", "reason": "Compromised account - ransomware"}},
        {"type": "send_notification", "context": {"channel": "security-critical", "message": "RANSOMWARE detected on {{source_host}}. Endpoint isolated. Immediate response required.", "severity": "critical"}},
        {"type": "create_ticket", "context": {"title": "CRITICAL: Ransomware - {{source_host}}", "description": "HYDRA detected ransomware activity (T1486). Endpoint has been isolated. User disabled. Investigation ID: {{investigation_id}}", "priority": "critical"}}
    ]',
    true,
    true,
    NULL
)
ON CONFLICT DO NOTHING;

-- 3. C2 Communication Response (trigger: T1071 + risk >= 75)
INSERT INTO response_playbooks (name, description, trigger_conditions, actions, requires_approval, enabled, tenant_id)
VALUES (
    'C2 Communication Response',
    'Response to command-and-control communication detection. Blocks destination domain, notifies SOC.',
    '{"verdict": "true_positive", "risk_score_gte": 75, "techniques_include": ["T1071"]}',
    '[
        {"type": "block_ip", "context": {"ip": "{{dest_ip}}", "duration_hours": 48, "reason": "C2 communication detected"}},
        {"type": "send_notification", "context": {"channel": "security", "message": "C2 communication detected to {{dest_ip}}. Domain blocked.", "severity": "high"}},
        {"type": "create_ticket", "context": {"title": "C2 Communication - {{dest_ip}}", "description": "HYDRA detected C2 communication (T1071). Destination blocked. Investigation ID: {{investigation_id}}", "priority": "high"}}
    ]',
    false,
    true,
    NULL
)
ON CONFLICT DO NOTHING;

-- 4. Lateral Movement Response (trigger: T1021 + risk >= 70)
INSERT INTO response_playbooks (name, description, trigger_conditions, actions, requires_approval, enabled, tenant_id)
VALUES (
    'Lateral Movement Response',
    'Response to lateral movement detection. Disables compromised user, notifies SOC.',
    '{"verdict": "true_positive", "risk_score_gte": 70, "techniques_include": ["T1021"]}',
    '[
        {"type": "disable_user", "context": {"username": "{{attacker_username}}", "reason": "Lateral movement detection - compromised account"}},
        {"type": "send_notification", "context": {"channel": "security", "message": "Lateral movement detected. User {{attacker_username}} disabled.", "severity": "high"}},
        {"type": "create_ticket", "context": {"title": "Lateral Movement - {{attacker_username}}", "description": "HYDRA detected lateral movement (T1021). Compromised user disabled. Investigation ID: {{investigation_id}}", "priority": "high"}}
    ]',
    true,
    true,
    NULL
)
ON CONFLICT DO NOTHING;

-- 5. Phishing Response (trigger: T1566 + risk >= 60)
INSERT INTO response_playbooks (name, description, trigger_conditions, actions, requires_approval, enabled, tenant_id)
VALUES (
    'Phishing Response',
    'Response to phishing detection. Quarantines email attachment, notifies SOC.',
    '{"verdict": "true_positive", "risk_score_gte": 60, "techniques_include": ["T1566"]}',
    '[
        {"type": "quarantine_file", "context": {"file_hash": "{{file_hash}}", "file_path": "{{file_path}}", "reason": "Phishing attachment"}},
        {"type": "send_notification", "context": {"channel": "security", "message": "Phishing detected. Attachment quarantined. Target: {{victim_email}}", "severity": "medium"}},
        {"type": "create_ticket", "context": {"title": "Phishing Attack Detected", "description": "HYDRA detected phishing activity (T1566). Attachment quarantined. Investigation ID: {{investigation_id}}", "priority": "medium"}}
    ]',
    false,
    true,
    NULL
)
ON CONFLICT DO NOTHING;
