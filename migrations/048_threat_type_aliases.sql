-- Migration 048: Persist threat_type aliases for SIEM corpus compatibility
-- Maps short SIEM task_type names to skill template threat_types arrays
-- Without this, DB reset loses aliases that were added at runtime

-- data_exfiltration → data-exfiltration-detection
UPDATE agent_skills SET threat_types = array_append(threat_types, 'data_exfiltration')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('data_exfiltration' = ANY(threat_types));

-- phishing → phishing-investigation
UPDATE agent_skills SET threat_types = array_append(threat_types, 'phishing')
WHERE skill_slug = 'phishing-investigation'
AND NOT ('phishing' = ANY(threat_types));

-- malware → ransomware-triage (closest match)
UPDATE agent_skills SET threat_types = array_append(threat_types, 'malware')
WHERE skill_slug = 'ransomware-triage'
AND NOT ('malware' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'ransomware')
WHERE skill_slug = 'ransomware-triage'
AND NOT ('ransomware' = ANY(threat_types));

-- brute_force → brute-force-investigation
UPDATE agent_skills SET threat_types = array_append(threat_types, 'brute_force')
WHERE skill_slug = 'brute-force-investigation'
AND NOT ('brute_force' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'broken_auth')
WHERE skill_slug = 'brute-force-investigation'
AND NOT ('broken_auth' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'idor')
WHERE skill_slug = 'brute-force-investigation'
AND NOT ('idor' = ANY(threat_types));

-- Web attack types → data-exfiltration-detection (catch-all for Juice Shop corpus)
UPDATE agent_skills SET threat_types = array_append(threat_types, 'sqli')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('sqli' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'xss')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('xss' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'path_traversal')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('path_traversal' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'command_injection')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('command_injection' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'ssrf')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('ssrf' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'file_upload')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('file_upload' = ANY(threat_types));

UPDATE agent_skills SET threat_types = array_append(threat_types, 'benign_activity')
WHERE skill_slug = 'data-exfiltration-detection'
AND NOT ('benign_activity' = ANY(threat_types));
