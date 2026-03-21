# HYDRA Benchmark Corpus — 200 Alerts

Generated: 2026-03-21

## Distribution

| Verdict | Count |
|---------|-------|
| true_positive | 55 |
| false_positive | 55 |
| suspicious | 50 |
| benign | 40 |
| **Total** | **200** |

## True Positive Coverage (11 alert types)

| Alert Type | Count |
|-----------|-------|
| brute_force | 5 |
| c2_beacon | 5 |
| data_exfiltration | 5 |
| defense_evasion | 5 |
| lateral_movement | 5 |
| malware | 5 |
| persistence | 5 |
| phishing | 5 |
| privilege_escalation | 5 |
| ransomware | 5 |
| reconnaissance | 5 |

## Difficulty Distribution

| Difficulty | Count |
|-----------|-------|
| easy | 72 |
| medium | 78 |
| hard | 50 |

## False Positive Scenarios

1. **malware**: Security researcher cloned internal pentest tools repo — AV quarantined tool, never executed
2. **brute_force**: k6 load testing tool running auth stress test from CI runner — all 401s expected
3. **malware**: Security researcher cloned internal pentest tools repo — AV quarantined tool, never executed
4. **brute_force**: k6 load testing tool running auth stress test from CI runner — all 401s expected
5. **c2_beacon**: Telegraf metrics agent sending data to InfluxDB — standard monitoring infrastructure
6. **ransomware**: Monthly backup archival using 7-Zip with AES encryption — scheduled job, not ransomware
7. **brute_force**: HashiCorp Vault rotating service account passwords per 90-day policy — scheduled job
8. **c2_beacon**: Telegraf metrics agent sending data to InfluxDB — standard monitoring infrastructure
9. **lateral_movement**: Engineer using bastion host to access production — MFA verified, authorized SSH key
10. **defense_evasion**: Ansible playbook temporarily disabling firewall for blue-green deployment switch — re-enabled immediately
11. **data_exfiltration**: Windows Server Backup scheduled task copying to backup server via SMB — approved job
12. **persistence**: Ansible deploying application as systemd service — standard deployment pattern
13. **lateral_movement**: Developer using authorized SSH tunnel to database for debugging — normal workflow
14. **reconnaissance**: Docker container health checks — localhost probes to standard service ports
15. **c2_beacon**: VirusTotal API integration polling for scan results — standard SOC tool
16. **defense_evasion**: Ansible playbook temporarily disabling firewall for blue-green deployment switch — re-enabled immediately
17. **privilege_escalation**: IT admin onboarding contractor per approved JIRA ticket — normal provisioning workflow
18. **malware**: Developer running Node.js app with debugger and installing npm packages — normal dev workflow
19. **ransomware**: Monthly backup archival using 7-Zip with AES encryption — scheduled job, not ransomware
20. **c2_beacon**: Windows Update checking for patches — legitimate Microsoft CDN with standard user-agent

## Suspicious Scenarios

1. **data_exfiltration**: Finance employee copying confidential report to USB — could be for meeting or data theft
2. **persistence**: Cron job piping remote script to bash — extremely suspicious but some monitoring tools use this pattern
3. **malware**: cmd.exe spawned from Outlook — could be macro execution or user running command from email link
4. **c2_beacon**: Query to 3-day-old domain — could be new legitimate SaaS or C2 infrastructure
5. **brute_force**: Impossible travel alert — but MFA passed; could be employee traveling or credential theft with MFA bypass
6. **defense_evasion**: svchost with wrong parent — strong indicator of process hollowing but could be process spawn race condition
7. **c2_beacon**: Query to 3-day-old domain — could be new legitimate SaaS or C2 infrastructure
8. **brute_force**: Failed as regular user then succeeded as admin — could be attacker pivoting or user switching accounts
9. **persistence**: Registry persistence — name suggests cloud sync app but path is unusual for legitimate software
10. **privilege_escalation**: lsass minidump via comsvcs.dll — classic credential dumping technique but also used by crash dump tools
11. **defense_evasion**: svchost with wrong parent — strong indicator of process hollowing but could be process spawn race condition
12. **brute_force**: MFA fatigue attack pattern — 5 denied pushes then acceptance; or user accidentally denied then approved
13. **malware**: cmd.exe spawned from Outlook — could be macro execution or user running command from email link
14. **lateral_movement**: First-time RDP from new source IP — anomalous but could be workstation change
15. **reconnaissance**: Admin share enumeration — normal for IT admins but also common attacker technique
