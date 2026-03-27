# ZOVARC Sandbox Security Model

**Version:** 1.1.0
**Last Updated:** March 2026

---

## Overview

ZOVARC generates and executes Python investigation code using local LLMs. Because LLM output is inherently untrusted, all generated code runs inside a hardened sandbox with four independent defense layers. This document describes each layer, what it blocks, and why.

---

## Defense Layer Architecture

```
Alert Code (LLM-generated Python)
        |
        v
  [Layer 1] AST Prefilter (static analysis, <1ms)
        |
        v
  [Layer 2] Docker Container (process isolation)
        |  --network=none
        |  --read-only
        |  --cap-drop=ALL
        |  --user=65534:65534 (nobody)
        |  --pids-limit=64
        |  --memory=512m
        |  --cpus=0.5
        |  --tmpfs /tmp:size=64m,noexec,nosuid
        |  --security-opt=no-new-privileges
        |
        v
  [Layer 3] Seccomp Profile (syscall filtering)
        |
        v
  [Layer 4] Kill Timer (120s hard timeout)
        |
        v
  Stdout JSON captured --> Verdict pipeline
```

---

## Layer 1: AST Prefilter

**File:** `sandbox/ast_prefilter.py`, also inlined in `worker/stages/execute.py`
**Policy:** `worker/stages/sandbox_policy.yaml`
**Latency:** <1ms

The AST prefilter parses the generated Python code into an abstract syntax tree and walks every node to check for forbidden patterns.

### Blocked Imports

The following module imports are rejected before any code executes:

| Module | Reason |
|--------|--------|
| `os` | Filesystem manipulation, process spawning, environment access |
| `sys` | Interpreter internals, stdin/stdout hijacking |
| `subprocess` | Arbitrary command execution |
| `socket` | Network connectivity (TCP, UDP, raw sockets) |
| `shutil` | Filesystem operations (copy, move, delete trees) |
| `importlib` | Dynamic module loading to bypass static checks |
| `pickle` | Arbitrary code execution via deserialization |
| `marshal` | Low-level serialization, code object manipulation |
| `ctypes` | Direct memory access, FFI to C libraries |
| `pty` | Pseudo-terminal allocation for shell access |
| `signal` | Process signal manipulation |

### Blocked Patterns

The following function call patterns are rejected via regex matching:

| Pattern | Reason |
|---------|--------|
| `__import__()` | Dynamic import bypasses AST import checks |
| `eval()` | Arbitrary code execution from strings |
| `exec()` | Arbitrary code execution from strings |

### Why AST and Not Regex Alone

Regex-based filtering can be evaded by string concatenation, encoding, or comment injection. AST analysis operates on the parsed syntax tree, which is immune to cosmetic obfuscation. An `import os` buried inside a triple-quoted string will not appear as an `ast.Import` node. Conversely, `__import__('o'+'s')` will be caught by the regex pattern for `__import__()`.

---

## Layer 2: Docker Container Isolation

**Configuration:** `worker/stages/execute.py` function `_run_in_sandbox()`

Each investigation's code executes inside a fresh Docker container that is created, executed, and destroyed within a single subprocess call. The container uses the `python:3.11-slim` base image with the following security constraints:

### Network Isolation: `--network=none`

The container has no network stack. There is no loopback interface, no DNS resolver, no TCP/UDP/ICMP capability. This is the single most important security control: even if all other layers fail, the code cannot exfiltrate data or contact external command-and-control infrastructure.

### Read-Only Filesystem: `--read-only`

The root filesystem is mounted read-only. The code cannot modify system binaries, install packages, or persist artifacts. A size-limited tmpfs is mounted at `/tmp` (64MB, noexec, nosuid) for temporary files that investigation scripts may need.

### Dropped Capabilities: `--cap-drop=ALL`

All Linux capabilities are removed. The container process cannot:
- Change file ownership (CAP_CHOWN)
- Bypass file read/write/execute permission checks (CAP_DAC_OVERRIDE)
- Bind to privileged ports (CAP_NET_BIND_SERVICE)
- Use raw sockets (CAP_NET_RAW)
- Perform system administration operations (CAP_SYS_ADMIN)
- Load kernel modules (CAP_SYS_MODULE)
- Use ptrace (CAP_SYS_PTRACE)

### Unprivileged User: `--user=65534:65534`

Code runs as UID 65534 (nobody), not root. Combined with dropped capabilities and no-new-privileges, there is no path to root inside the container.

### Resource Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| `--cpus=0.5` | Half a CPU core | Prevent CPU monopolization |
| `--memory=512m` | 512MB RAM | Prevent memory exhaustion |
| `--memory-swap=512m` | No swap | Memory limit is hard ceiling |
| `--pids-limit=64` | 64 processes | Prevent fork bombs |
| `--security-opt=no-new-privileges` | Enabled | Block setuid escalation |

---

## Layer 3: Seccomp Profile

**File:** `sandbox/seccomp_profile.json`

The seccomp (secure computing) profile is a Linux kernel feature that filters system calls at the kernel level. ZOVARC uses a custom profile based on Docker's default but with additional restrictions for the investigation sandbox.

### Default Action

The profile uses `SCMP_ACT_ERRNO` as the default action, meaning any syscall not explicitly allowed returns an error. This is a whitelist approach: only known-safe syscalls are permitted.

### Explicitly Blocked Syscalls

These syscalls are blocked regardless of arguments:

| Syscall | Risk |
|---------|------|
| `mount` | Filesystem manipulation, container escape |
| `ptrace` | Process inspection, debugger attachment, container escape |
| `kexec_load` | Load and execute a new kernel |
| `kexec_file_load` | Load and execute a new kernel (file-based) |
| `reboot` | System restart |
| `setns` | Enter another namespace (container escape) |
| `unshare` | Create new namespaces (privilege escalation) |
| `bpf` | BPF program loading (kernel-level code execution) |
| `perf_event_open` | Performance monitoring (side-channel attacks) |

### Conditionally Blocked Syscalls

| Syscall | Condition | Risk |
|---------|-----------|------|
| `socket` | Raw socket type (domain 40) blocked | Raw network access |
| `clone` / `clone3` | CLONE_NEWUSER flag blocked | User namespace escape |

### Allowed Syscalls

The following categories of syscalls are explicitly allowed, as they are required for Python interpreter operation:

- **File I/O:** open, read, write, close, stat, fstat, lseek, mmap, etc.
- **Memory management:** brk, mmap, mprotect, munmap, mremap
- **Process lifecycle:** exit, exit_group, wait4, fork, vfork, execve
- **Signals:** rt_sigaction, rt_sigprocmask, rt_sigreturn, kill, tgkill
- **Time:** clock_gettime, nanosleep, gettimeofday
- **IPC:** pipe, pipe2, eventfd, futex

### Why Not Block All Network Syscalls?

The seccomp profile allows socket, connect, bind, listen, accept, sendto, recvfrom, sendmsg, and recvmsg because Python's internal operations (logging, random number generation, multiprocessing) may use Unix domain sockets or pipe-based IPC. Network isolation is enforced at the Docker level via `--network=none`, which removes the network namespace entirely. The seccomp profile blocks raw sockets as an additional defense against any hypothetical network namespace re-creation.

---

## Layer 4: Kill Timer

**File:** `sandbox/kill_timer.py`, also implemented in `worker/stages/execute.py`
**Timeout:** 120 seconds (configurable via `sandbox_policy.yaml`)

The kill timer is a hard execution deadline enforced via Python's `subprocess.run(timeout=...)` parameter. If the Docker container does not exit within the timeout period, the subprocess is terminated, which triggers Docker to remove the container.

This prevents:
- Infinite loops
- Intentional stalling (sleep-based time wasting)
- Resource exhaustion attacks that stay within memory limits but monopolize CPU
- Cryptomining or other compute-intensive abuse

---

## Sandbox Policy Configuration

**File:** `worker/stages/sandbox_policy.yaml`

The sandbox policy is a declarative YAML file that controls all sandbox parameters. This design allows security teams to audit and customize the sandbox configuration without modifying Python source code.

```yaml
version: "1.0"
ast_prefilter:
  blocked_imports:
    - os
    - sys
    - subprocess
    - socket
    # ... (full list in file)
  blocked_patterns:
    - "__import__("
    - "eval("
    - "exec("
process:
  max_execution_seconds: 120
  max_memory_mb: 512
```

Changes to the sandbox policy take effect on the next worker restart. No code changes are required.

---

## What Can the Sandbox Code Do?

The investigation code inside the sandbox CAN:

- Read data passed via stdin (alert payload, log snippets)
- Perform string parsing, regex matching, JSON processing
- Use Python standard library modules (re, json, collections, datetime, math, statistics, hashlib, base64, ipaddress, urllib.parse)
- Write results as JSON to stdout
- Use /tmp for temporary file operations (up to 64MB)
- Run for up to 120 seconds

The investigation code CANNOT:

- Make any network connections (no HTTP, DNS, TCP, UDP, ICMP)
- Read or write files outside /tmp
- Spawn persistent processes
- Access host filesystem, environment variables, or Docker socket
- Install packages or modify the Python environment
- Execute shell commands
- Load kernel modules or modify system configuration
- Access other containers or the host network namespace

---

## Security Audit Checklist

For organizations evaluating ZOVARC's sandbox model, verify:

- [ ] `--network=none` is present in the Docker run command
- [ ] `--read-only` is present in the Docker run command
- [ ] `--cap-drop=ALL` is present in the Docker run command
- [ ] `--security-opt=no-new-privileges` is present
- [ ] `--user=65534:65534` runs as unprivileged user
- [ ] seccomp profile blocks mount, ptrace, kexec_load
- [ ] AST prefilter blocks os, sys, subprocess, socket imports
- [ ] Kill timer is set to a reasonable value (default: 120s)
- [ ] sandbox_policy.yaml is reviewed and approved by security team
- [ ] LLM audit log captures all generated code for review
