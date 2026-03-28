# ZOVARK — Cold Outreach Email Templates

## Template 1: EU Bank (GDPR Angle)

**Subject:** Air-gapped SOC AI — no data leaves your network (GDPR Article 44 compliant)

Dear [Name],

I'm reaching out because [Bank Name]'s security team faces a challenge I've been working on: AI-assisted SOC investigation that doesn't require sending security telemetry to a US cloud provider.

GDPR Article 44 restricts cross-border data transfers, which blocks your team from using CrowdStrike Charlotte AI, Microsoft Copilot for Security, or any cloud-dependent investigation tool. Meanwhile, your analysts spend 30-60 minutes per alert on manual triage.

We built ZOVARK — an autonomous investigation platform that runs entirely on-premise. A local LLM generates investigation code for each alert, executes it in a hardened sandbox, and delivers structured verdicts with IOCs and MITRE ATT&CK mapping. No data leaves your network. No cloud dependency.

The numbers: 99% accuracy on 100 real-traffic attacks (OWASP Juice Shop), correct verdicts on novel attack types including Kerberoasting and LOLBins abuse, runs on a single NVIDIA GPU.

I'd like to offer a 30-day pilot: your SIEM webhooks (Splunk or Elastic), your alerts, your hardware. We handle deployment. Your team evaluates accuracy against ground truth.

Would 15 minutes this week work to discuss?

Best,
[Name]

---

## Template 2: US Healthcare (HIPAA Angle)

**Subject:** SOC automation that keeps PHI on-premise — HIPAA-ready

Dear [Name],

[Health System Name] processes thousands of security alerts daily across your clinical and IT infrastructure. Your SOC team triages each one manually because HIPAA's minimum necessary standard prevents sending security logs — which may contain PHI — to cloud AI services.

We built ZOVARK specifically for this constraint. It's an autonomous SOC investigation platform that runs entirely on your infrastructure:

- Local LLM (no cloud API calls, no BAA required with AI vendors)
- Hardened sandbox execution (4-layer isolation for generated investigation code)
- Structured verdicts with IOCs, evidence citations, and MITRE ATT&CK mapping
- Splunk and Elastic webhook integration (connects to your existing SIEM)

Performance: 99% accuracy on real-traffic attacks, 10/10 correct verdicts on novel attack types (Kerberoasting, certutil LOLBins, timestomping), average investigation time under 2 minutes.

We're offering 30-day pilots to 3 healthcare SOC teams. You provide: SIEM webhook access, one GPU server (any NVIDIA 8GB+), one analyst for weekly accuracy review. We provide: deployment, integration, and ongoing support.

No data leaves your environment. No per-query pricing. No BAA with an AI cloud provider.

Is this something your team would evaluate?

Best,
[Name]

---

## Template 3: Defense Contractor (CMMC Angle)

**Subject:** CUI-safe SOC automation — no cloud, no data egress, runs on your SIPR

Dear [Name],

[Company Name]'s SOC team handles alerts across environments that process controlled unclassified information. CMMC Level 2 (and NIST 800-171) requires that CUI stays within your authorization boundary — which rules out every cloud-based AI investigation tool on the market.

We built ZOVARK for exactly this scenario. It's an autonomous SOC investigation engine that runs completely air-gapped:

- **Local inference:** Quantized LLM on a single NVIDIA GPU. No internet required after deployment.
- **Air-gap tested:** Bundled MITRE ATT&CK and CISA KEV databases. No outbound connections.
- **Sandbox isolation:** 4-layer code containment (AST analysis, seccomp, network deny-all, kill timer).
- **Novel attack handling:** Generates investigation code for never-before-seen attack patterns — not just classification.

We validated against real attacks: 10/10 correct verdicts including Kerberoasting (T1558.003), LOLBins certutil (T1105), and defense evasion timestomping (T1070.006). 99% overall on a 100-alert OWASP benchmark.

The deployment footprint: 6 Docker containers, one GPU server, Splunk or Elastic webhook integration. Kubernetes manifests and Helm charts included for production.

We're looking for 2-3 defense contractor SOC teams for a 30-day pilot. Everything stays on your network. We provide deployment support and weekly accuracy reviews.

Would your team be open to a 15-minute technical overview?

Best,
[Name]
