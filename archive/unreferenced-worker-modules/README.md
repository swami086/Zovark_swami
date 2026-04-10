# Unreferenced worker modules (archived)

These files were moved out of `worker/` because they were not imported from
`worker/main.py`, had no API routes, and were not covered by runtime or test paths.

| Original path | Archived as |
|---------------|-------------|
| `worker/reporting/export.py` | `reporting_export.py` |
| `worker/retention/purge_job.py` | `purge_job.py` |
| `worker/realtime/collaboration.py` | `collaboration.py` |

Restore to `worker/` and wire registration only if you intend to ship the feature.
