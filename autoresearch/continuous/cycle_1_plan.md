# Cycle 1 Work Plan
Generated: 2026-04-01T09:15:00Z

## Critical Issues (fix before anything else)
None - no CRITICAL issues found.

## Track 1 targets (from HIGH issues)
1. **stage.assess latency** (p95=24.3s) - The assess stage is taking 24+ seconds
   - Approach: Examine worker/stages/assess.py for optimization opportunities
   - Look for redundant LLM calls, slow regex patterns, or blocking operations
   
2. **llm.call latency** (p95=24.2s) - LLM calls are the bottleneck
   - Approach: Check llm_client.py for concurrency issues
   - Verify Semaphore(2) is working correctly
   - Check if model is loaded on GPU vs CPU

3. **No third HIGH issue** - System is otherwise healthy
   - Focus on latency optimization

## Track 3 template targets (lowest Path A rate task types)
- Current: 100% using "tools" execution mode (v3 pipeline)
- No Path A templates are being matched (all go through v3 tool pipeline)
- **Action**: Investigate why investigation_plans.json isn't being used
- Task types needing templates: c2_communication_hunt, brute_force, kerberoasting

## Track 4 tool targets (tools with errors in traces)
- **No tool errors found** - 0 errors in last 6h
- Skip tool hardening this cycle (no data)

## Track 6 test targets (lowest coverage files)
- Need to run coverage analysis
- Target: worker/stages/assess.py (has latency issues, needs coverage)

## Key Metrics from Telemetry
- 12 investigations in last 24h
- 100% detection rate (9/9 attacks detected)
- 0% false positive rate (2/2 benign correctly classified)
- 0 workflow failures
- 0 open bypasses
