# ZOVARK Conference Submission Abstracts

**Prepared:** March 2026
**Contact:** ZOVARK Development Team

---

## 1. Black Hat USA 2026 Arsenal

**Title:** ZOVARK: Live Air-Gapped SOC Investigation with Local LLMs on a $300 GPU

**Track:** Arsenal (Tool Demonstration)

**Abstract:**

We demonstrate ZOVARK, an autonomous SOC investigation platform that runs entirely on air-gapped infrastructure with zero cloud connectivity. ZOVARK receives SIEM alerts, generates Python investigation code using a locally-hosted 14B-parameter language model, executes that code in a hardened sandbox (AST prefiltering, Docker isolation, seccomp filtering, network removal), and delivers structured verdicts with MITRE ATT&CK mapping, risk scores, and IOC extraction. The live demonstration runs on a single NVIDIA RTX 3050 laptop GPU with 4GB VRAM---hardware that costs under $300 at retail---processing real-time alerts from OWASP Juice Shop. Attendees will observe the complete investigation lifecycle: alert ingestion, PII masking, template-based code generation, sandbox execution with network isolation, LLM-powered verdict generation, and dashboard visualization. We benchmark at 100% attack detection rate across SQL injection, XSS, authentication bypass, directory traversal, and brute force alert categories, with an average investigation time of 95 seconds. The four-layer sandbox model is designed to contain adversarial LLM output: we will show live examples of the AST prefilter blocking attempted os.system() and subprocess.call() injections. ZOVARK addresses the market gap between cloud-dependent AI SOC platforms (CrowdStrike Charlotte AI, Microsoft Copilot for Security) and organizations bound by GDPR, HIPAA, NERC CIP, or CMMC data sovereignty requirements. The complete LLM audit trail provides investigation provenance for compliance review. Source code and deployment scripts are available for immediate evaluation.

---

## 2. DEF CON 32 Demo Labs

**Title:** Breaking and Defending the AI SOC: Sandbox Security for LLM-Generated Investigation Code

**Track:** Demo Labs

**Abstract:**

What happens when you let an AI write and execute security investigation code on your infrastructure? ZOVARK is an open-source SOC automation platform that generates Python investigation scripts using local language models and runs them in sandboxed containers. This demonstration explores both the offensive and defensive sides of LLM-powered security operations. On defense, we present a four-layer containment model: (1) AST prefiltering that statically analyzes Python abstract syntax trees to block forbidden imports and dangerous patterns before execution; (2) Docker containers with no network stack, read-only filesystems, and dropped capabilities; (3) custom seccomp profiles that block mount, ptrace, kexec_load, and raw socket syscalls; (4) kill timers that forcefully terminate runaway processes. On offense, we demonstrate attack vectors against LLM-generated code: prompt injection via malicious alert payloads, obfuscated import evasion attempts, encoded payload techniques, and resource exhaustion attacks. Each attack is shown alongside the specific defense layer that catches it. The demonstration runs entirely offline on a single laptop with an RTX 3050 GPU, using Qwen2.5-14B via llama.cpp. We process live alerts through the complete five-stage investigation pipeline (ingest, analyze, execute, assess, store) and show the full audit trail that connects each verdict to its source model, prompt, and execution context. Attendees will leave understanding both the real capabilities and the genuine limitations of local LLM security automation.

---

## 3. BSides Las Vegas 2026

**Title:** SOC Automation on a Budget: Autonomous Investigation with a $300 GPU and Zero Cloud Dependencies

**Track:** Main Track Presentation

**Abstract:**

Enterprise SOC teams process thousands of alerts daily while data sovereignty regulations prohibit sending telemetry to cloud AI services. Every major AI-assisted investigation platform---CrowdStrike Charlotte AI, Microsoft Copilot for Security, Google Chronicle SOAR---requires cloud connectivity, leaving compliance-constrained organizations without AI-powered triage capabilities. We present ZOVARK, a fully reproducible SOC investigation platform that runs on consumer hardware. Our reference deployment uses a single NVIDIA RTX 3050 (4GB VRAM, retail price approximately $300) running a quantized Qwen2.5-14B model via llama.cpp. The complete stack---Go API gateway, Python investigation worker, Temporal workflow engine, PostgreSQL database, Redis cache, React dashboard---deploys via a single docker-compose command with no external dependencies. We share concrete benchmark results from 100 OWASP Juice Shop real-traffic attack alerts: 100% attack detection rate on 69 completed investigations, 95-second average investigation time, and zero data egress. We document every limitation honestly: 31% of investigations timed out due to single-GPU queuing, false positive discrimination needs calibration, IOC extraction accuracy is inconsistent, and the DPO fine-tuning pipeline is built but not yet applied. This talk is for SOC engineers and security architects evaluating whether local LLM automation is ready for production. We provide the complete source code, benchmark corpus, deployment scripts, and hardware requirements so that any attendee can reproduce our results on their own hardware within an afternoon. No vendor lock-in, no cloud subscription, no data leaves your network.

---

## Submission Metadata

**Primary Author Availability:** June-August 2026
**Demo Hardware Requirements:** Single laptop with NVIDIA GPU (RTX 3050 or better), external monitor, power outlet
**Software Requirements:** Docker Desktop, llama.cpp (pre-installed), no internet connectivity required during demo
**Travel:** Flexible, self-funded
