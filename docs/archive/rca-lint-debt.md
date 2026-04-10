# RCA: Lint Debt Accumulated Over Sprints 1A-3A

**Date:** 2026-03-06
**Severity:** Low (CI failure, no production impact)
**Status:** Resolved (commit 88f2c26)

---

## 1. Incident Summary

- **164 flake8 errors** found when the CI pipeline (Sprint 3A) ran for the first time
- CI lint job failed on every push from Sprint 3A through the lint fix commit
- 3 of 4 CI jobs passed (build, validate-migrations, test-imports); only lint failed
- All errors were style/hygiene — zero functional bugs

## 2. Root Causes

### RC-1: No linter in the development loop (Sprints 1A-2B)

13 sprints of code written without any static analysis. Definition of done was functional ("does the worker start, does the workflow complete"). No flake8/pylint/ruff in requirements.txt, Dockerfile, or pre-commit hooks.

### RC-2: Windows CRLF line endings

Development on Windows host produced `\r\n` line endings in all files. Python executes fine with CRLF, but flake8 flags every blank line containing `\r` as W293 (blank line contains whitespace). This accounted for **~100 of 164 errors (61%)**. Root: no `.gitattributes` forcing LF, no `.editorconfig`, no pre-commit hook.

### RC-3: AI-generated code style gaps

Claude Code generates working Python but doesn't follow PEP 8 strictly. Common patterns:
- Single blank line between top-level functions (E302 requires 2)
- Unused imports left after refactoring (F401)
- Unused variables from copy-paste or defensive coding (F841)
- Sprint prompts never included "run flake8 before committing"

### RC-4: Lint added last, not first

CI pipeline was Sprint 3A (19th sprint), not Sprint 1A. By the time the linter ran, there were 6,449 lines of Python with accumulated style debt. If linting had been in place from Sprint 1A, each sprint would have fixed its own errors incrementally.

## 3. What Was Fixed

**179 errors across 41 Python files reduced to 0.**

| Error Type | Count | Description |
|-----------|-------|-------------|
| W293 | ~100 | Blank lines containing `\r` whitespace (CRLF) |
| E302 | ~25 | Missing 2 blank lines before top-level definitions |
| E303 | ~15 | Too many blank lines inside functions |
| F401 | 9 | Unused imports (json, time, psycopg2, os, field, builtins, activity) |
| F841 | 8 | Unused variables (task_type, litellm_url, api_key, edges, step_number, tenant_id, task_id) |
| W291 | ~10 | Trailing whitespace on code lines |
| E701 | 5 | Multiple statements on one line |
| E261 | 2 | Single space before inline comment |
| E305 | 2 | Missing 2 blank lines after function before module-level code |
| F541 | 2 | f-string with no placeholders |
| F821 | 1 | Undefined name `_get_db` (fixed to `get_db_connection`) |
| W391 | 1 | Blank line at end of file |

### Near-miss: F821 undefined name

One error — `F821 undefined name '_get_db'` in `worker/_legacy_activities.py` (historically `activities.py`) — was a real bug, not just style. The `check_rate_limit_activity` function called `_get_db()` which didn't exist in that file. Fixed by changing to `get_db_connection()` which is the correct function defined at the top of the file. This would have caused a runtime `NameError` if the rate limit DB lookup path was exercised.

## 4. Prevention Measures Implemented

| Measure | File | Effect |
|---------|------|--------|
| CI lint job | `.github/workflows/ci.yml` | flake8 runs on every push and PR |
| Git line ending enforcement | `.gitattributes` | Forces LF for .py, .sql, .yaml, .yml, .md, .json, .sh |
| Editor config | `.editorconfig` | LF line endings, UTF-8, trim trailing whitespace |

## 5. Recommended Additional Measures

- Add `ruff` to `requirements.txt` as a faster alternative to flake8 (10-100x faster)
- Add pre-commit hooks: `pip install pre-commit` + `.pre-commit-config.yaml`
- Add lint step to every future sprint prompt: "Run flake8 before committing"
- Consider `ruff format` for auto-formatting on save

## 6. Impact Assessment

- **Production impact:** None — all 164 errors were style/hygiene
- **CI impact:** Lint job blocked for ~2 hours between Sprint 3A push and fix commit
- **Data impact:** Zero — database row counts unchanged (138 investigations, 304 entities, 14 detection rules, 5 playbooks)
- **One real bug found:** F821 `_get_db` undefined — would have caused runtime error on rate limit DB path

## 7. Health Check Results (Post-Fix)

| Check | Result |
|-------|--------|
| flake8 | 0 errors |
| All module imports | OK (20 modules) |
| Prompt registry | 10 prompts registered |
| Rate limiter | Acquire/release cycle OK |
| Injection detector | clean/suspicious classification OK |
| Entity normalization | IP/domain normalization OK |
| LiteLLM health | 200 OK |
| Embedding server | 200 OK, dim=768 |
| Database row counts | Unchanged |
| API health | status: ok |
| Worker logs | 6 workflows, 51 activities registered |
