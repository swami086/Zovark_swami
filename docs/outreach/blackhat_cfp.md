# ZOVARK: The Air-Gapped AI SOC Agent
## BlackHat Arsenal Submission

### Abstract

AI SOC agents — Intezer, Dropzone, Prophet, Torq — have proven that autonomous alert investigation works. SOC teams using these tools report 60-80% reduction in analyst triage time. But regulated enterprises under GDPR Article 44, HIPAA 164.312, and CMMC Level 3 cannot use them. Alert data cannot legally leave the organization's network for cloud AI processing.

ZOVARK is the first AI SOC agent purpose-built for air-gapped deployment. It runs entirely on customer hardware — a single NVIDIA GPU, PostgreSQL, and Docker. No cloud dependency. No data egress. Zero internet connectivity required.

Unlike classification-based detection tools, ZOVARK generates custom Python investigation code for each alert. When it encounters an attack type it has never seen — Kerberoasting, Golden Ticket, DLL sideloading — it writes investigation code, executes it in a 4-layer sandbox (AST prefilter, seccomp profile, network isolation, resource limits), and returns a structured verdict with IOCs traced to exact log lines.

### Key Results
- 100% attack detection rate across 983 investigations — zero false negatives
- 22 attack types including 10 novel TTPs with no templates
- Under 1% false positive rate on 200-alert benign calibration
- Evidence citations linking every IOC to source log data
- MITRE ATT&CK mapping on every investigation

### Demo
Live investigation of a Kerberoasting attack (T1558.003) with no template, no prior training. The audience watches ZOVARK:
1. Receive a raw SIEM alert
2. Generate Python investigation code in real time
3. Execute in a sandboxed container
4. Return a structured verdict with IOC extraction and MITRE mapping

Total time: ~60 seconds on A100 GPU.

### Technical Architecture
- Go API gateway (Gin) + Python investigation worker (Temporal SDK)
- 5-stage pipeline: Ingest → Analyze → Execute → Assess → Store
- LLM confined to exactly 2 stages (code generation + assessment)
- PostgreSQL 16 + pgvector for entity graph and semantic search
- 4-layer sandbox: AST prefilter → seccomp → Docker network=none → kill timer
- ~65,000 LOC across ~450 files

### Category
Incident Detection & Response / AI & Machine Learning

### Speaker
[Your name and bio]
