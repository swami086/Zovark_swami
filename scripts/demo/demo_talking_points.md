# Zovark Demo — 2-Minute Talking Points

## 00:00 — Opening
"Zovark is an autonomous SOC investigation platform. It runs completely air-gapped — no cloud, no data leaves your network. Local LLM generates investigation code, executes it in a hardened sandbox, and delivers structured verdicts."

## 00:15 — Scene 1: Brute Force Alert
"Watch: I submit an SSH brute force alert — 500 failed logins from an Eastern European IP targeting root."
[Submit alert, wait for result]
"In 15 seconds, Zovark identified the attacker IP 185.220.101.45, confirmed it's a true positive with risk score 95, and recommended blocking at the perimeter firewall."

## 00:45 — Scene 2: Lateral Movement
"Now a more sophisticated attack — Pass-the-Hash from a finance workstation to the domain controller using mimikatz."
[Submit alert, wait for result]
"Zovark detected the NTLM credential abuse, flagged svc_backup as compromised, identified the lateral movement path, and recommended immediate isolation."

## 01:05 — Scene 3: Benign Noise
"Now watch what happens with routine noise."
[Submit password_change alert]
"Password change by j.smith. Risk 15. Benign. No analyst time wasted. Your SOC gets 500 of these a day. Zovark ignores them all in under a second."

## 01:20 — The Numbers
"Catches real attacks. Ignores noise. On your hardware. 99% accuracy on 100 real-traffic Juice Shop attacks. 11 investigation templates. MITRE ATT&CK mapped. Runs on a single NVIDIA GPU."

## 01:30 — Architecture
"Go API, Python workers, Temporal for durable execution, PostgreSQL with pgvector for entity correlation. Docker sandbox with seccomp, AST prefilter, network isolation."

## 01:45 — Call to Action
"We're looking for 2-3 SOC teams for a 30-day pilot. Real SIEM webhooks from Splunk or Elastic, real alerts, real investigations. Air-gapped, on your hardware."

## 02:00 — End
