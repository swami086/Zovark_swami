-- migrations/015_sprint5_seed_skills_and_validation.sql
-- Sprint 5: Seed 5 core MSSP investigation types (if not already present)
-- Also adds validate_generated_code and enrich_alert_with_memory to audit_events

-- Update audit_events CHECK to add Sprint 5 event types
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (event_type IN (
    'investigation_started', 'investigation_completed', 'code_executed',
    'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
    'entity_extracted', 'detection_generated', 'user_login', 'user_registered',
    'injection_detected', 'cross_tenant_hit', 'threat_score_updated',
    'self_healing_scan', 'self_healing_diagnosis', 'self_healing_patch_applied',
    'self_healing_patch_failed', 'self_healing_rollback',
    'dry_run_validation_failed', 'memory_enrichment_applied'
));

-- Seed skills if table is empty (safe no-op if already populated)
DO $$
BEGIN
    IF (SELECT count(*) FROM agent_skills) > 0 THEN
        RAISE NOTICE 'agent_skills already has % rows, skipping seed', (SELECT count(*) FROM agent_skills);
        RETURN;
    END IF;

    INSERT INTO agent_skills (
        skill_name, skill_slug, is_community, threat_types, mitre_tactics, mitre_techniques,
        severity_default, investigation_methodology, detection_patterns, example_prompt
    ) VALUES
    ('Brute Force Investigation', 'brute-force-investigation', true,
     ARRAY['brute_force', 'credential_stuffing'],
     ARRAY['TA0006'],
     ARRAY['T1110', 'T1110.001', 'T1110.002', 'T1110.003', 'T1110.004'],
     'high',
     'Analyze login patterns, source IPs, targeted accounts, success/failure ratios.',
     'Multiple failed logins from single IP; password spray across accounts; credential stuffing with leaked databases.',
     'Investigate 847 failed SSH login attempts from 203.0.113.50 targeting server admin accounts.'),

    ('Malware Triage', 'malware-triage', true,
     ARRAY['malware', 'ransomware'],
     ARRAY['TA0002', 'TA0003'],
     ARRAY['T1204', 'T1204.002', 'T1059', 'T1547'],
     'critical',
     'Analyze file hashes, process execution chains, network callbacks, persistence mechanisms.',
     'Suspicious process execution; file hash matches known malware; outbound C2 connections.',
     'Endpoint alert: svchost_update.exe encrypting files on WORKSTATION-042. Outbound to 198.51.100.77:4443.'),

    ('Phishing Analysis', 'phishing-analysis', true,
     ARRAY['phishing', 'social_engineering'],
     ARRAY['TA0001'],
     ARRAY['T1566', 'T1566.001', 'T1566.002'],
     'medium',
     'Analyze sender domains, URLs, attachments, recipient interaction patterns.',
     'Spoofed sender domain; malicious URL in body; weaponized attachment.',
     'Suspicious email from invoice-update@acm3corp.com with attachment Q3_Report.pdf.exe.'),

    ('Lateral Movement Detection', 'lateral-movement-detection', true,
     ARRAY['lateral_movement'],
     ARRAY['TA0008'],
     ARRAY['T1021', 'T1021.001', 'T1021.002', 'T1076'],
     'high',
     'Analyze authentication patterns across hosts, RDP/SMB connections, credential usage.',
     'Unusual RDP connections; pass-the-hash; SMB lateral spread.',
     'Detect RDP connections from compromised workstation WKSTN-12 to 5 internal servers.'),

    ('C2 Communication Hunt', 'c2-communication-hunt', true,
     ARRAY['c2', 'command_and_control'],
     ARRAY['TA0011'],
     ARRAY['T1071', 'T1071.001', 'T1071.004', 'T1573'],
     'critical',
     'Analyze beaconing patterns, DNS tunneling, unusual outbound connections.',
     'Regular interval beaconing; DNS query anomalies; encrypted C2 channels.',
     'Investigate regular 60-second beaconing from endpoint to 198.51.100.23:443.');

    RAISE NOTICE 'Seeded 5 investigation skills into agent_skills';
END $$;
