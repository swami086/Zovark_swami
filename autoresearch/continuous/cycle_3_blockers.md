# Cycle 3 Blockers

## CRITICAL: 4 Complete Bypasses Found

### Bypass 1: RT002_PERSISTENCE_002 — COM Hijacking
**Input:** Registry modification for COM hijacking
**Expected:** true_positive, risk >= 75
**Actual:** benign, risk = 0
**Root Cause:** The tool detection patterns don't recognize COM hijacking registry paths
**Fix Required:** Add COM hijacking detection to privilege_escalation hunt tools

### Bypass 2: RT002_PERSISTENCE_004 — Encoded Service Command
**Input:** Base64 encoded PowerShell in service ImagePath
**Expected:** true_positive, risk >= 80
**Actual:** benign, risk = 0
**Root Cause:** Detection pattern requires literal "powershell" or "encodedcommand" - base64 evades this
**Fix Required:** Add base64 detection to service analysis

### Bypass 3: RT002_PERSISTENCE_008 — Token Impersonation via RunAs
**Input:** RunAs with saved credentials and encoded command
**Expected:** true_positive, risk >= 85
**Actual:** benign, risk = 0
**Root Cause:** No detection for runas.exe with /savecred and encoded payloads
**Fix Required:** Add runas detection patterns

### Bypass 4: RT002_PERSISTENCE_009 — AppCert DLLs
**Input:** AppCertDlls registry modification
**Expected:** true_positive, risk >= 85
**Actual:** benign, risk = 0
**Root Cause:** AppCertDlls persistence mechanism not in detection patterns
**Fix Required:** Add AppCertDlls registry path detection

## Partial Detections (8 vectors)
Risk scores below expected minimum but verdict correct:
- RT001_TIMING_004: risk 45 (expected 60)
- RT001_TIMING_005: risk 70 (expected 75)
- RT001_TIMING_008: risk 70 (expected 90)
- RT002_PERSISTENCE_001: risk 70 (expected 80)
- RT002_PERSISTENCE_003: risk 70 (expected 85)
- RT002_PERSISTENCE_005: risk 70 (expected 85)
- RT002_PERSISTENCE_007: risk 70 (expected 80)
- RT002_PERSISTENCE_010: risk 70 (expected 80)

## Action Plan
1. Add new detection patterns to worker/tools/detection.py
2. Update scoring in worker/tools/scoring.py for persistence attacks
3. Re-run evaluate.py to verify fixes
4. Target: 0 bypasses, 100% detection
