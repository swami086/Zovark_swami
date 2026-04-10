# Archive

Historical documents from earlier ZOVARK versions. These are kept for reference but are no longer current.

Where an archived doc mentions **ExecuteTaskWorkflow** or monolithic **`worker/workflows.py`**, the current equivalent is **`InvestigationWorkflowV2`** in **`worker/stages/investigation_workflow.py`** (see **`worker/stages/register.py`**). Core activities moved to **`worker/_legacy_activities.py`**. Removed dashboard components (**LiveInvestigationFeed**, **SovereigntyBanner**, **DemoSelector**, **GuardrailScoreBar**) are not coming back from these snapshots—use **SSE** on **`TaskList` / `TaskDetail`** and **`/demo`** as in `CLAUDE.md`.

- **audit-reports/** — Security audits from v0.10.0 and v0.10.1
- **sprints/** — Sprint implementation reports
- **dev-sessions/** — Development session artifacts and prompt archives
