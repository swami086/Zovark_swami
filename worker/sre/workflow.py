"""Self-Healing SRE Workflow — orchestrates failure scan, diagnosis, patching, testing, and application."""

from datetime import timedelta
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from sre.monitor import scan_for_failures
    from sre.diagnose import diagnose_failure
    from sre.patcher import generate_patch
    from sre.tester import test_patch
    from sre.applier import apply_patch


@workflow.defn
class SelfHealingWorkflow:
    @workflow.run
    async def run(self, params: dict) -> dict:
        lookback_minutes = params.get("lookback_minutes", 30)
        dry_run = params.get("dry_run", True)

        # 1. Scan for failures
        scan_result = await workflow.execute_activity(
            scan_for_failures,
            {"lookback_minutes": lookback_minutes},
            schedule_to_close_timeout=timedelta(minutes=2),
        )

        failures = scan_result.get("failures", [])
        workflow.logger.info(f"SRE scan complete: {scan_result['count']} failures found")

        if not failures:
            return {
                "status": "ok",
                "failures_found": 0,
                "healed": 0,
                "failed_to_heal": 0,
                "dry_run": dry_run,
            }

        healed = 0
        failed_to_heal = 0
        details = []

        # 2. Process each failure
        for failure in failures:
            try:
                # 2a. Diagnose
                diagnosis = await workflow.execute_activity(
                    diagnose_failure,
                    failure,
                    schedule_to_close_timeout=timedelta(minutes=2),
                )

                workflow.logger.info(
                    f"Diagnosed {failure.get('workflow_id', '?')}: "
                    f"{diagnosis.get('category', '?')} — auto_fixable={diagnosis.get('auto_fixable', False)}"
                )

                if not diagnosis.get("auto_fixable", False):
                    failed_to_heal += 1
                    details.append({
                        "workflow_id": failure.get("workflow_id"),
                        "category": diagnosis.get("category"),
                        "status": "not_fixable",
                        "reason": diagnosis.get("root_cause", ""),
                    })
                    continue

                # 2b. Generate patch
                patch = await workflow.execute_activity(
                    generate_patch,
                    diagnosis,
                    schedule_to_close_timeout=timedelta(minutes=3),
                )

                if patch.get("type") == "no_patch":
                    failed_to_heal += 1
                    details.append({
                        "workflow_id": failure.get("workflow_id"),
                        "category": diagnosis.get("category"),
                        "status": "no_patch",
                        "reason": patch.get("reason", ""),
                    })
                    continue

                # 2c. Test patch
                test_result = await workflow.execute_activity(
                    test_patch,
                    patch,
                    schedule_to_close_timeout=timedelta(minutes=1),
                )

                if not test_result.get("passed", False):
                    failed_to_heal += 1
                    details.append({
                        "workflow_id": failure.get("workflow_id"),
                        "category": diagnosis.get("category"),
                        "status": "test_failed",
                        "reason": test_result.get("stderr", test_result.get("reason", "")),
                    })
                    continue

                # 2d. Apply patch (only if not dry_run)
                apply_data = {**patch}
                apply_data["dry_run"] = dry_run
                apply_data["workflow_id"] = failure.get("workflow_id", "")
                apply_data["activity_name"] = failure.get("activity_name", "")
                apply_data["error_category"] = diagnosis.get("category", "")
                apply_data["diagnosis"] = diagnosis
                apply_data["test_result"] = test_result

                apply_result = await workflow.execute_activity(
                    apply_patch,
                    apply_data,
                    schedule_to_close_timeout=timedelta(seconds=30),
                )

                if apply_result.get("applied") or apply_result.get("dry_run"):
                    healed += 1
                    details.append({
                        "workflow_id": failure.get("workflow_id"),
                        "category": diagnosis.get("category"),
                        "status": "healed" if apply_result.get("applied") else "dry_run",
                        "patch_type": patch.get("type"),
                        "file_path": apply_result.get("file_path", ""),
                    })
                else:
                    failed_to_heal += 1
                    details.append({
                        "workflow_id": failure.get("workflow_id"),
                        "category": diagnosis.get("category"),
                        "status": "apply_failed",
                        "reason": apply_result.get("reason", ""),
                    })

            except Exception as e:
                failed_to_heal += 1
                details.append({
                    "workflow_id": failure.get("workflow_id", ""),
                    "status": "error",
                    "reason": str(e)[:200],
                })
                workflow.logger.info(f"SRE error processing failure: {e}")

        result = {
            "status": "completed",
            "failures_found": len(failures),
            "healed": healed,
            "failed_to_heal": failed_to_heal,
            "dry_run": dry_run,
            "details": details,
        }
        workflow.logger.info(f"SRE workflow complete: {result['healed']} healed, {result['failed_to_heal']} failed")
        return result
