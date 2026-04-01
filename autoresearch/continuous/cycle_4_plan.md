# Cycle 4 Work Plan
Generated: 2026-04-01T12:30:00Z

## Debt to Clear (from Cycles 1-3)
- [ ] Track 3: Templates — Add ≥3 templates
- [ ] Track 4: Tool Hardening — Run harness on ≥3 tools  
- [ ] Track 5: Benchmark Gate — Run test_benchmark.py
- [ ] Track 6: Test Coverage — Add ≥5 tests

## Track 3: Template Growth
**Problem:** Path A rate is 0% — all investigations use "tools" mode
**Root Cause:** `investigation_plan` field not populated in `agent_skills` table
**Action:** Skip DB templates for now (requires schema migration), focus on validating `investigation_plans.json` is being loaded correctly

## Track 4: Tool Hardening
**Target Tools:**
1. `detect_com_hijacking` — just added, needs edge cases
2. `detect_encoded_service` — just added, needs edge cases
3. `detect_token_impersonation` — just added, needs edge cases

## Track 5: Benchmark Gate
**Command:** `pytest worker/tests/test_benchmark.py -v`
**Must Pass:** 100% detection, 0% FP

## Track 6: Test Coverage
**Target:** Add 5 tests for new detection tools
**Files:**
- `worker/tools/tests/test_detection.py` — add tests for 4 new tools
