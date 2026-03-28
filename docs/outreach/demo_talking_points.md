# Zovark — 2-Minute CISO Demo Script

## Setup
- Dashboard open at localhost:5173
- Terminal ready for curl commands
- Redis flushed: `docker compose exec redis redis-cli -a zovark-redis-dev-2026 FLUSHDB`
- Token obtained

## Script

**00:00** — "You've seen what AI SOC agents like Intezer and Dropzone can do — autonomous investigation, structured verdicts, triage in seconds. Zovark does the same thing, on your hardware. No cloud. No data egress."

**00:15** — [Submit brute_force alert]
"500 failed SSH login attempts from 185.220.101.45. Watch."
→ Result: true_positive, risk=100. "Under a second. Attacker IP extracted, evidence cited, MITRE T1110 mapped."

**00:30** — [Submit password_change alert]
"Now routine noise. Password change by j.smith."
→ Result: benign, risk=15. "Dismissed instantly. Zero analyst time. Your SOC gets 500 of these a day — Zovark ignores all of them."

**00:50** — [Submit lateral_movement alert]
"Pass-the-Hash attack. mimikatz.exe in the parent process."
→ Result: true_positive, risk=95. "svc_backup account, NTLM hash detected. Full evidence chain. MITRE T1550."

**01:10** — [Submit kerberoasting alert — Path C, no template]
"Now something Zovark has never seen. Kerberoasting — no template, no prior training."
→ Wait ~60-90s on A100 (mention this). Result: true_positive, risk=85+.
"It wrote Python investigation code, ran it in a sandbox, and caught it. That's the differentiator — it investigates attack types it's never been trained on."

**01:40** — "100% attack detection across 983 investigations. 22 attack types. Under 1% false positive rate. Runs on standard enterprise hardware. GDPR, HIPAA, and CMMC compliant by architecture — because no data ever leaves your network."

**01:55** — "We're looking for 3 SOC teams for a 30-day pilot. Your SIEM. Your alerts. Nothing leaves your network. If 90% of verdicts are accurate, we talk pricing."
