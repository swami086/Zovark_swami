-- Migration 041: Network Beaconing skill — C2 beacon detection + DNS tunneling
-- Adds a new agent_skill for Zeek conn.log/DNS log analysis.
-- Uses INSERT ... ON CONFLICT to be idempotent.

INSERT INTO agent_skills (
    skill_name,
    skill_slug,
    is_community,
    threat_types,
    mitre_tactics,
    mitre_techniques,
    severity_default,
    applicable_log_sources,
    investigation_methodology,
    detection_patterns,
    example_prompt,
    keywords,
    code_template,
    parameters
) VALUES (
    'C2 Network Beacon Detection',
    'network-beaconing',
    true,
    ARRAY['c2_communication', 'command_and_control', 'data_exfiltration'],
    ARRAY['TA0011'],
    ARRAY['T1071', 'T1071.004', 'T1095', 'T1572'],
    'critical',
    ARRAY['zeek_conn', 'zeek_dns', 'firewall', 'proxy', 'dns'],
    'Analyze Zeek connection and DNS logs for C2 beaconing patterns using statistical jitter analysis, DNS subdomain entropy measurement, and port-protocol mismatch detection. Groups connections by (src, dst, port) tuple, computes inter-arrival interval coefficient of variation, and flags flows with jitter below threshold as automated beacons. For DNS, measures Shannon entropy of subdomain strings to detect tunneling and data exfiltration channels.',
    'Periodic outbound connections with low jitter (coefficient of variation < 0.15); DNS queries with unusually long subdomains (>20 chars) and high entropy (>3.5 bits); connections to non-standard ports (4444, 8080, 8443, 1337, 31337); TXT record queries to the same base domain; long-lived SSL/TLS sessions to rare external IPs.',
    'Investigate regular 300-second beaconing from 10.0.0.50 to 198.51.100.23:443 with DNS queries to randomized subdomains of c2-beacon.evil.com.',
    ARRAY['beacon', 'beaconing', 'c2', 'command_and_control', 'dns_tunnel', 'dns_tunneling', 'jitter', 'zeek', 'conn.log', 'dns.log', 'periodic', 'interval'],
    -- code_template loaded from worker/skills/network_beaconing.py via seed_templates.py
    NULL,
    '[{"name": "log_data", "type": "string", "default": ""},
      {"name": "beacon_jitter_threshold", "type": "float", "default": 0.15},
      {"name": "dns_entropy_threshold", "type": "float", "default": 3.5},
      {"name": "dns_length_threshold", "type": "integer", "default": 20},
      {"name": "min_beacon_count", "type": "integer", "default": 5},
      {"name": "suspicious_ports", "type": "array", "default": [4444, 8080, 8443, 1337, 31337, 9001, 5555]},
      {"name": "watch_ips", "type": "array", "default": []}]'::jsonb
)
ON CONFLICT (tenant_id, skill_slug, version) DO UPDATE SET
    skill_name = EXCLUDED.skill_name,
    threat_types = EXCLUDED.threat_types,
    mitre_techniques = EXCLUDED.mitre_techniques,
    investigation_methodology = EXCLUDED.investigation_methodology,
    detection_patterns = EXCLUDED.detection_patterns,
    keywords = EXCLUDED.keywords,
    parameters = EXCLUDED.parameters,
    updated_at = NOW();
