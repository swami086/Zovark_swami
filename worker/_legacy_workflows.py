import json
from datetime import timedelta
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from activities import (
        fetch_task, generate_code, validate_code, execute_code,
        update_task_status, log_audit, log_audit_event, record_usage,
        save_investigation_step, check_followup_needed, generate_followup_code,
        check_requires_approval, create_approval_request, update_approval_request,
        retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template,
        check_rate_limit_activity, decrement_active_activity, heartbeat_lease_activity,
        validate_generated_code, enrich_alert_with_memory
    )
    from entity_graph import extract_entities, write_entity_graph, embed_investigation
    from intelligence.blast_radius import compute_blast_radius
    from intelligence.fp_analyzer import analyze_false_positive
    from intelligence.cross_tenant import get_entity_intelligence
    from reporting.incident_report import generate_incident_report
    from response.workflow import ResponsePlaybookWorkflow, find_matching_playbooks
    # Prompt v2: retry loop for IOC extraction
    try:
        from dpo.prompts_v2 import PromptAssembler as _PromptAssembler, should_retry as _should_retry, generate_retry_hints as _generate_retry_hints
        _retry_assembler = _PromptAssembler()
    except ImportError:
        _retry_assembler = None
        _should_retry = None
        _generate_retry_hints = None
    from response.auto_trigger import auto_trigger_playbooks
    from security.injection_detector import scan_for_injection
    from security.prompt_sanitizer import wrap_untrusted_data
    from security.risk_validator import validate_risk_score
    from pii_detector import mask_for_llm, unmask_response

MAX_STEPS = 3


def _verdict_from_severity(severity: str) -> str:
    """Map severity level to investigation verdict."""
    mapping = {
        "critical": "true_positive",
        "high": "true_positive",
        "medium": "suspicious",
        "low": "benign",
        "informational": "benign",
    }
    return mapping.get(severity, "inconclusive")


@workflow.defn
class ExecuteTaskWorkflow:
    def __init__(self):
        self._approval_decision = None

    @workflow.signal
    async def approval_decision(self, data: dict):
        self._approval_decision = data

    @workflow.run
    async def run(self, task_request: dict) -> dict:
        info = workflow.info()
        task_id = info.workflow_id.replace("task-", "")
        task_data = await workflow.execute_activity(
            fetch_task,
            task_id,
            schedule_to_close_timeout=timedelta(seconds=10)
        )

        tenant_id = task_data.get("tenant_id")
        task_type = task_data.get("task_type", "log_analysis").lower().replace(" ", "_")

        # Lease-based rate limit check (reads max_concurrent from tenants table)
        rate_ok = await workflow.execute_activity(
            check_rate_limit_activity,
            {"tenant_id": tenant_id, "task_id": task_id},
            schedule_to_close_timeout=timedelta(seconds=10)
        )
        if not rate_ok:
            return await self._fail_task(task_id, tenant_id, "Rate limited: tenant at maximum concurrent investigations")

        try:
            return await self._run_investigation(task_id, tenant_id, task_type, task_data)
        finally:
            await workflow.execute_activity(
                decrement_active_activity,
                {"tenant_id": tenant_id, "task_id": task_id},
                schedule_to_close_timeout=timedelta(seconds=10)
            )

    async def _run_investigation(self, task_id, tenant_id, task_type, task_data):
        await workflow.execute_activity(
            log_audit,
            {
                "tenant_id": tenant_id,
                "action": "workflow_started",
                "resource_type": "task",
                "resource_id": task_id
            },
            schedule_to_close_timeout=timedelta(seconds=10)
        )
        await workflow.execute_activity(
            log_audit_event,
            {
                "tenant_id": tenant_id,
                "event_type": "investigation_started",
                "actor_type": "system",
                "resource_type": "task",
                "resource_id": task_id,
                "metadata": {"task_type": task_type}
            },
            schedule_to_close_timeout=timedelta(seconds=10)
        )

        # --- SKILLS RAG RETRIEVAL ---
        skill_used_id = None
        skill_template = None
        skill_params = []
        current_prompt = task_data.get("input", {}).get("prompt", "")

        try:
            retrieved_skill = await workflow.execute_activity(
                retrieve_skill,
                args=[task_type, current_prompt],
                schedule_to_close_timeout=timedelta(seconds=15)
            )
            workflow.logger.info(f"DEBUG: retrieved_skill result is {retrieved_skill}")
            if retrieved_skill:
                skill_used_id = retrieved_skill.get("id")
                skill_name = retrieved_skill.get("skill_name", "")
                skill_methodology = retrieved_skill.get("investigation_methodology", "")
                skill_detection = retrieved_skill.get("detection_patterns", "")
                mitre_tech = retrieved_skill.get("mitre_techniques", [])
                skill_template = retrieved_skill.get("code_template")
                skill_params = retrieved_skill.get("parameters", [])

                RagSystemOverride = f"""You are a senior security analyst with access to your organization's investigation knowledge base.

=== INVESTIGATION SKILL: {skill_name} ===
Methodology:
{skill_methodology}

Detection Patterns:
{skill_detection}

Relevant MITRE ATT&CK Techniques: {mitre_tech}
=== END SKILL ===

Follow this methodology when generating your detection script.
If something has worked in past investigations for this threat type, apply those patterns first."""

                existing_override = task_data.get("input", {}).get("playbook_system_prompt_override", "")
                if existing_override:
                    task_data["input"]["playbook_system_prompt_override"] = existing_override + "\n\n" + RagSystemOverride
                else:
                    if "input" not in task_data:
                        task_data["input"] = {}
                    task_data["input"]["playbook_system_prompt_override"] = RagSystemOverride

                # Context Window Management
                current_log_data = task_data.get("input", {}).get("log_data", "")
                if current_log_data:
                    skill_tokens = len(RagSystemOverride.split()) * 1.33
                    log_tokens = len(current_log_data.split()) * 1.33
                    prompt_tokens = len(current_prompt.split()) * 1.33
                    total_tokens = skill_tokens + log_tokens + prompt_tokens + 500

                    if total_tokens > 6000:
                        allowed_log_tokens = 6000 - skill_tokens - 500
                        allowed_words = int(allowed_log_tokens / 1.33)
                        if allowed_words > 0:
                            lines = current_log_data.split('\n')
                            kept_lines = []
                            word_count = 0
                            for ln in lines:
                                ln_words = len(ln.split())
                                if word_count + ln_words > allowed_words:
                                    break
                                kept_lines.append(ln)
                                word_count += ln_words
                            task_data["input"]["log_data"] = "\n".join(kept_lines) + "\n... [truncated for context limit]"

        except Exception as e:
            workflow.logger.info(f"Failed to retrieve skill: {str(e)}")
            # Do nothing if it fails, never fail the workflow

        # --- INJECTION DETECTION (Sprint 1L) ---
        injection_confidence = "clean"
        try:
            scan_text = current_prompt + " " + task_data.get("input", {}).get("log_data", "")
            siem_event = task_data.get("input", {}).get("siem_event")
            if siem_event:
                scan_text += " " + json.dumps(siem_event)
            scan_result = scan_for_injection(scan_text)
            injection_confidence = scan_result.confidence_source
            if scan_result.is_suspicious:
                workflow.logger.info(
                    f"Injection scan: {scan_result.confidence_source}, "
                    f"categories={scan_result.matched_patterns}"
                )
                await workflow.execute_activity(
                    log_audit_event,
                    {
                        "tenant_id": tenant_id,
                        "event_type": "injection_detected",
                        "actor_type": "system",
                        "resource_type": "task",
                        "resource_id": task_id,
                        "metadata": {
                            "confidence_source": scan_result.confidence_source,
                            "matched_patterns": scan_result.matched_patterns,
                            "match_count": len(scan_result.raw_matches),
                        }
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
                # BLOCK: reject task when injection is detected
                return await self._fail_task(
                    task_id, tenant_id,
                    f"Prompt injection detected ({scan_result.confidence_source}). "
                    f"Task quarantined. Matched patterns: {scan_result.matched_patterns}"
                )
        except Exception as e:
            workflow.logger.info(f"Injection scan failed non-fatally: {e}")

        # --- WRAP UNTRUSTED DATA (Sprint 1L) ---
        try:
            log_data = task_data.get("input", {}).get("log_data", "")
            if log_data:
                wrapped_log, safety_instruction = wrap_untrusted_data(log_data, "telemetry")
                task_data["input"]["log_data"] = wrapped_log
                existing_override = task_data.get("input", {}).get("playbook_system_prompt_override", "")
                if existing_override:
                    task_data["input"]["playbook_system_prompt_override"] = existing_override + "\n\n" + safety_instruction
                else:
                    if "input" not in task_data:
                        task_data["input"] = {}
                    task_data["input"]["playbook_system_prompt_override"] = safety_instruction
        except Exception as e:
            workflow.logger.info(f"Prompt wrapping failed non-fatally: {e}")

        # --- STEP 0: MEMORY ENRICHMENT (Sprint 5) ---
        memory_context = {}
        try:
            memory_context = await workflow.execute_activity(
                enrich_alert_with_memory,
                task_data,
                schedule_to_close_timeout=timedelta(seconds=10)
            )
            if memory_context.get('exact_matches') or memory_context.get('similar_entities'):
                workflow.logger.info(
                    f"Memory enrichment: {len(memory_context.get('exact_matches', []))} exact, "
                    f"{len(memory_context.get('similar_entities', []))} similar matches"
                )
                # Inject memory context into task_data for code generation prompt
                if "input" not in task_data:
                    task_data["input"] = {}
                task_data["input"]["memory_context"] = memory_context
        except Exception as e:
            workflow.logger.info(f"Memory enrichment failed non-fatally: {e}")

        # --- PII MASKING (Security P0#2) ---
        pii_entity_map_key = None
        try:
            prompt_text = task_data.get("input", {}).get("prompt", "")
            log_data = task_data.get("input", {}).get("log_data", "")
            siem_json = json.dumps(task_data.get("input", {}).get("siem_event", {})) if task_data.get("input", {}).get("siem_event") else ""
            pii_input_text = f"{prompt_text}\n{log_data}\n{siem_json}".strip()

            if pii_input_text:
                pii_result = await workflow.execute_activity(
                    mask_for_llm,
                    {"prompt_text": pii_input_text, "tenant_id": tenant_id, "task_id": task_id},
                    schedule_to_close_timeout=timedelta(seconds=15)
                )
                if pii_result.get("pii_count", 0) > 0:
                    pii_entity_map_key = pii_result["entity_map_key"]
                    masked_text = pii_result["masked_text"]
                    # Replace the original data with masked versions
                    parts = masked_text.split("\n", 2)
                    if len(parts) >= 1 and parts[0]:
                        task_data["input"]["prompt"] = parts[0]
                    if len(parts) >= 2 and parts[1]:
                        task_data["input"]["log_data"] = parts[1]
                    workflow.logger.info(f"PII masked: {pii_result['pii_count']} items detected")
        except Exception as e:
            workflow.logger.info(f"PII masking failed non-fatally: {e}")

        # Accumulators across all steps
        total_tokens_input = 0
        total_tokens_output = 0
        total_exec_ms = 0
        final_stdout = ""
        final_code = ""
        current_prompt = task_data.get("input", {}).get("prompt", "")
        previous_context = ""
        completed_steps = 0
        previous_risk_score = 0

        playbook_steps = task_data.get("input", {}).get("playbook_steps")
        max_loop_steps = min(len(playbook_steps), MAX_STEPS) if playbook_steps else MAX_STEPS

        for step_num in range(1, max_loop_steps + 1):
            if playbook_steps:
                current_prompt = playbook_steps[step_num - 1]

            step_type = "analysis" if step_num == 1 else ("enrichment" if step_num == 2 else "deep_analysis")

            # --- GENERATE CODE ---
            is_template = False
            template_params_used = {}
            try:
                if step_num == 1 and skill_template:
                    is_template = True
                    fill_result = await workflow.execute_activity(
                        fill_skill_parameters,
                        {
                            "skill_params": skill_params,
                            "prompt": current_prompt,
                            "log_data": task_data.get("input", {}).get("log_data", ""),
                            "siem_event": task_data.get("input", {}).get("siem_event", {})
                        },
                        schedule_to_close_timeout=timedelta(minutes=5)
                    )
                    template_params_used = fill_result["filled_parameters"]

                    code = await workflow.execute_activity(
                        render_skill_template,
                        {
                            "template": skill_template,
                            "parameters": template_params_used
                        },
                        schedule_to_close_timeout=timedelta(minutes=1)
                    )
                    llm_exec_ms = fill_result["execution_ms"]
                    step_tokens_in = fill_result["input_tokens"]
                    step_tokens_out = fill_result["output_tokens"]

                elif step_num == 1:
                    gen_result = await workflow.execute_activity(
                        generate_code,
                        task_data,
                        schedule_to_close_timeout=timedelta(minutes=5)
                    )
                    code = gen_result["code"]
                    usage = gen_result["usage"]
                    llm_exec_ms = gen_result["execution_ms"]
                    step_tokens_in = usage.get("prompt_tokens", 0)
                    step_tokens_out = usage.get("completion_tokens", 0)

                    # Heartbeat lease after code generation
                    try:
                        await workflow.execute_activity(
                            heartbeat_lease_activity,
                            {"tenant_id": tenant_id, "task_id": task_id},
                            schedule_to_close_timeout=timedelta(seconds=5)
                        )
                    except Exception:
                        pass
                else:
                    gen_result = await workflow.execute_activity(
                        generate_followup_code,
                        {
                            "prompt": current_prompt,
                            "previous_context": previous_context,
                            "task_type": task_type,
                            "step_number": step_num,
                            "playbook_system_prompt_override": task_data.get("input", {}).get("playbook_system_prompt_override")
                        },
                        schedule_to_close_timeout=timedelta(minutes=5)
                    )
                    code = gen_result["code"]
                    usage = gen_result["usage"]
                    llm_exec_ms = gen_result["execution_ms"]
                    step_tokens_in = usage.get("prompt_tokens", 0)
                    step_tokens_out = usage.get("completion_tokens", 0)

            except Exception as e:
                await workflow.execute_activity(
                    save_investigation_step,
                    {
                        "task_id": task_id,
                        "step_number": step_num,
                        "step_type": step_type,
                        "prompt": current_prompt,
                        "status": "failed",
                        "output": str(e),
                        "execution_mode": "template" if is_template else "generated",
                        "parameters_used": template_params_used
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
                if step_num == 1:
                    return await self._fail_task(task_id, tenant_id, f"Code generation failed: {str(e)}")
                break

            await workflow.execute_activity(
                record_usage,
                {
                    "tenant_id": tenant_id,
                    "task_id": task_id,
                    "record_type": "llm_call",
                    "model_name": "fast",
                    "tokens_input": step_tokens_in,
                    "tokens_output": step_tokens_out,
                    "execution_ms": llm_exec_ms
                },
                schedule_to_close_timeout=timedelta(seconds=10)
            )

            # --- VALIDATE CODE ---
            val_result = await workflow.execute_activity(
                validate_code,
                code,
                schedule_to_close_timeout=timedelta(seconds=10)
            )

            if not val_result["is_safe"]:
                await workflow.execute_activity(
                    save_investigation_step,
                    {
                        "task_id": task_id,
                        "step_number": step_num,
                        "step_type": step_type,
                        "prompt": current_prompt,
                        "generated_code": code,
                        "status": "failed",
                        "output": f"Security validation failed: {val_result['reason']}",
                        "tokens_used_input": step_tokens_in,
                        "tokens_used_output": step_tokens_out,
                        "execution_ms": llm_exec_ms,
                        "execution_mode": "template" if is_template else "generated",
                        "parameters_used": template_params_used
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
                if step_num == 1:
                    return await self._fail_task(
                        task_id, tenant_id, f"Security validation failed: {val_result['reason']}",
                        tokens_input=step_tokens_in, tokens_output=step_tokens_out, exec_ms=llm_exec_ms
                    )
                break

            # --- DRY-RUN VALIDATION GATE (Sprint 5) ---
            if not is_template:
                try:
                    dry_run = await workflow.execute_activity(
                        validate_generated_code,
                        code,
                        schedule_to_close_timeout=timedelta(seconds=15)
                    )
                    if not dry_run['passed']:
                        workflow.logger.info(f"Dry-run failed: {dry_run.get('reason')}. Retrying code gen.")
                        # One retry with validation feedback
                        retry_data = dict(task_data)
                        if "input" not in retry_data:
                            retry_data["input"] = {}
                        retry_data["input"]["validation_feedback"] = dry_run['reason']
                        gen_result2 = await workflow.execute_activity(
                            generate_code,
                            retry_data,
                            schedule_to_close_timeout=timedelta(minutes=5)
                        )
                        code = gen_result2["code"]
                        usage2 = gen_result2["usage"]
                        step_tokens_in += usage2.get("prompt_tokens", 0)
                        step_tokens_out += usage2.get("completion_tokens", 0)

                        # Re-validate AST
                        val_result2 = await workflow.execute_activity(
                            validate_code,
                            code,
                            schedule_to_close_timeout=timedelta(seconds=10)
                        )
                        if not val_result2["is_safe"]:
                            if step_num == 1:
                                return await self._fail_task(
                                    task_id, tenant_id,
                                    f"Security validation failed after retry: {val_result2['reason']}",
                                    tokens_input=step_tokens_in, tokens_output=step_tokens_out, exec_ms=llm_exec_ms
                                )
                            break

                        # Second dry-run
                        dry_run2 = await workflow.execute_activity(
                            validate_generated_code,
                            code,
                            schedule_to_close_timeout=timedelta(seconds=15)
                        )
                        if not dry_run2['passed']:
                            workflow.logger.info(f"Dry-run failed twice: {dry_run2.get('reason')}")
                            if step_num == 1:
                                return await self._fail_task(
                                    task_id, tenant_id,
                                    f"Code validation failed twice: {dry_run2['reason']}",
                                    tokens_input=step_tokens_in, tokens_output=step_tokens_out, exec_ms=llm_exec_ms
                                )
                            break
                except Exception as e:
                    workflow.logger.info(f"Dry-run gate error (non-fatal): {e}")

            # --- APPROVAL GATE ---
            approval_check = await workflow.execute_activity(
                check_requires_approval,
                {
                    "task_type": task_type,
                    "risk_score": previous_risk_score,
                    "code": code,
                    "step_number": step_num
                },
                schedule_to_close_timeout=timedelta(seconds=10)
            )

            if approval_check["required"]:
                # Create approval request
                approval_id = await workflow.execute_activity(
                    create_approval_request,
                    {
                        "task_id": task_id,
                        "step_number": step_num,
                        "risk_level": approval_check["risk_level"],
                        "action_summary": approval_check["reason"],
                        "generated_code": code
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )

                # Update task status to awaiting_approval
                await workflow.execute_activity(
                    update_task_status,
                    {
                        "task_id": task_id,
                        "status": "awaiting_approval",
                        "tokens_input": total_tokens_input + step_tokens_in,
                        "tokens_output": total_tokens_output + step_tokens_out,
                        "execution_ms": total_exec_ms + llm_exec_ms
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )

                await workflow.execute_activity(
                    log_audit,
                    {
                        "tenant_id": tenant_id,
                        "action": "approval_requested",
                        "resource_type": "task",
                        "resource_id": task_id,
                        "details": {
                            "approval_id": approval_id,
                            "risk_level": approval_check["risk_level"],
                            "reason": approval_check["reason"],
                            "step_number": step_num
                        }
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
                await workflow.execute_activity(
                    log_audit_event,
                    {
                        "tenant_id": tenant_id,
                        "event_type": "approval_requested",
                        "actor_type": "system",
                        "resource_type": "task",
                        "resource_id": task_id,
                        "metadata": {"approval_id": approval_id, "risk_level": approval_check["risk_level"]}
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )

                # Wait for approval signal (24 hour timeout)
                self._approval_decision = None
                try:
                    await workflow.wait_condition(
                        lambda: self._approval_decision is not None,
                        timeout=timedelta(hours=24)
                    )
                except TimeoutError:
                    pass  # Timeout — will be handled below

                if self._approval_decision is None:
                    # Timeout — auto-reject
                    await workflow.execute_activity(
                        update_approval_request,
                        {
                            "approval_id": approval_id,
                            "status": "rejected",
                            "comment": "Approval timed out after 24 hours"
                        },
                        schedule_to_close_timeout=timedelta(seconds=10)
                    )
                    return await self._fail_task(
                        task_id, tenant_id, "Approval timed out after 24 hours",
                        tokens_input=total_tokens_input + step_tokens_in,
                        tokens_output=total_tokens_output + step_tokens_out,
                        exec_ms=total_exec_ms + llm_exec_ms
                    )

                if not self._approval_decision.get("approved", False):
                    # Rejected
                    comment = self._approval_decision.get("comment", "Rejected by reviewer")
                    await workflow.execute_activity(
                        update_approval_request,
                        {
                            "approval_id": approval_id,
                            "status": "rejected",
                            "decided_by": self._approval_decision.get("decided_by"),
                            "comment": comment
                        },
                        schedule_to_close_timeout=timedelta(seconds=10)
                    )
                    await workflow.execute_activity(
                        log_audit,
                        {
                            "tenant_id": tenant_id,
                            "action": "approval_rejected",
                            "resource_type": "task",
                            "resource_id": task_id,
                            "details": {"comment": comment}
                        },
                        schedule_to_close_timeout=timedelta(seconds=10)
                    )
                    await workflow.execute_activity(
                        log_audit_event,
                        {
                            "tenant_id": tenant_id,
                            "event_type": "approval_denied",
                            "actor_id": self._approval_decision.get("decided_by"),
                            "actor_type": "user",
                            "resource_type": "task",
                            "resource_id": task_id,
                            "metadata": {"comment": comment}
                        },
                        schedule_to_close_timeout=timedelta(seconds=10)
                    )
                    # Save step as rejected
                    await workflow.execute_activity(
                        save_investigation_step,
                        {
                            "task_id": task_id,
                            "step_number": step_num,
                            "step_type": step_type,
                            "prompt": current_prompt,
                            "generated_code": code,
                            "status": "rejected",
                            "output": f"Rejected: {comment}",
                            "tokens_used_input": step_tokens_in,
                            "tokens_used_output": step_tokens_out,
                            "execution_ms": llm_exec_ms
                        },
                        schedule_to_close_timeout=timedelta(seconds=10)
                    )
                    await workflow.execute_activity(
                        update_task_status,
                        {
                            "task_id": task_id,
                            "status": "rejected",
                            "error_message": comment,
                            "tokens_input": total_tokens_input + step_tokens_in,
                            "tokens_output": total_tokens_output + step_tokens_out,
                            "execution_ms": total_exec_ms + llm_exec_ms
                        },
                        schedule_to_close_timeout=timedelta(seconds=10)
                    )
                    return {"status": "rejected", "comment": comment}

                # Approved — continue to execution
                await workflow.execute_activity(
                    update_approval_request,
                    {
                        "approval_id": approval_id,
                        "status": "approved",
                        "decided_by": self._approval_decision.get("decided_by"),
                        "comment": self._approval_decision.get("comment", "Approved")
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
                await workflow.execute_activity(
                    log_audit,
                    {
                        "tenant_id": tenant_id,
                        "action": "approval_approved",
                        "resource_type": "task",
                        "resource_id": task_id,
                        "details": {"comment": self._approval_decision.get("comment", "Approved")}
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
                await workflow.execute_activity(
                    log_audit_event,
                    {
                        "tenant_id": tenant_id,
                        "event_type": "approval_granted",
                        "actor_id": self._approval_decision.get("decided_by"),
                        "actor_type": "user",
                        "resource_type": "task",
                        "resource_id": task_id,
                        "metadata": {"comment": self._approval_decision.get("comment", "Approved")}
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )

                # Update task status back to executing
                await workflow.execute_activity(
                    update_task_status,
                    {
                        "task_id": task_id,
                        "status": "executing"
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )

                # Reset for next potential approval
                self._approval_decision = None

            # --- EXECUTE CODE ---
            try:
                exec_result = await workflow.execute_activity(
                    execute_code,
                    code,
                    schedule_to_close_timeout=timedelta(minutes=2)
                )
            except Exception as e:
                await workflow.execute_activity(
                    save_investigation_step,
                    {
                        "task_id": task_id,
                        "step_number": step_num,
                        "step_type": step_type,
                        "prompt": current_prompt,
                        "generated_code": code,
                        "output": final_stdout,
                        "status": "failed",
                        "tokens_used_input": step_tokens_in,
                        "tokens_used_output": step_tokens_out,
                        "execution_ms": llm_exec_ms,
                        "execution_mode": "template" if is_template else "generated",
                        "parameters_used": template_params_used
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
                if step_num == 1:
                    return await self._fail_task(
                        task_id, tenant_id, f"Code execution error: {str(e)}",
                        tokens_input=step_tokens_in, tokens_output=step_tokens_out, exec_ms=llm_exec_ms
                    )
                break

            step_exec_ms = llm_exec_ms + exec_result["execution_ms"]

            # Heartbeat lease after code execution
            try:
                await workflow.execute_activity(
                    heartbeat_lease_activity,
                    {"tenant_id": tenant_id, "task_id": task_id},
                    schedule_to_close_timeout=timedelta(seconds=5)
                )
            except Exception:
                pass

            await workflow.execute_activity(
                record_usage,
                {
                    "tenant_id": tenant_id,
                    "task_id": task_id,
                    "record_type": "skill_exec",
                    "model_name": "sandbox",
                    "execution_ms": exec_result["execution_ms"]
                },
                schedule_to_close_timeout=timedelta(seconds=10)
            )

            stdout_str = exec_result["stdout"]
            step_status = "completed" if exec_result["status"] == "completed" else "failed"

            # --- SAVE STEP IMMEDIATELY (crash recovery) ---
            await workflow.execute_activity(
                save_investigation_step,
                {
                    "task_id": task_id,
                    "step_number": step_num,
                    "step_type": step_type,
                    "prompt": current_prompt,
                    "generated_code": code,
                    "output": stdout_str,
                    "status": "completed",
                    "tokens_used_input": step_tokens_in,
                    "tokens_used_output": step_tokens_out,
                    "execution_ms": llm_exec_ms + exec_result["execution_ms"],
                    "execution_mode": "template" if is_template else "generated",
                    "parameters_used": template_params_used
                },
                schedule_to_close_timeout=timedelta(seconds=10)
            )

            await workflow.execute_activity(
                log_audit_event,
                {
                    "tenant_id": tenant_id,
                    "event_type": "code_executed",
                    "actor_type": "worker",
                    "resource_type": "task",
                    "resource_id": task_id,
                    "metadata": {"step_number": step_num, "status": step_status}
                },
                schedule_to_close_timeout=timedelta(seconds=10)
            )

            # Accumulate totals
            total_tokens_input += step_tokens_in
            total_tokens_output += step_tokens_out
            total_exec_ms += step_exec_ms
            final_stdout = stdout_str
            final_code = code
            completed_steps = step_num

            # Extract risk_score for next step's approval check
            try:
                parsed_out = json.loads(stdout_str)
                if isinstance(parsed_out, dict):
                    rs = parsed_out.get("risk_score")
                    if rs is not None:
                        previous_risk_score = int(rs)
            except Exception:
                pass

            if exec_result["status"] == "failed":
                if step_num == 1:
                    return await self._fail_task(
                        task_id, tenant_id, f"Sandbox failed: {exec_result['stderr']}",
                        tokens_input=total_tokens_input, tokens_output=total_tokens_output, exec_ms=total_exec_ms
                    )
                break

            # --- IOC RETRY LOOP (prompts v2) ---
            # If step 1 succeeded but extracted 0 IOCs, retry once with the failure visible.
            # Manus principle: "keep the wrong stuff in" — show model its own output and ask to fix.
            if (step_num == 1 and _should_retry is not None and _retry_assembler is not None
                    and not is_template):
                try:
                    parsed_for_retry = json.loads(stdout_str)
                    if isinstance(parsed_for_retry, dict):
                        # Normalize: check both "iocs" and "indicators_of_compromise"
                        retry_check = dict(parsed_for_retry)
                        if "iocs" not in retry_check and "indicators_of_compromise" in retry_check:
                            retry_check["iocs"] = retry_check["indicators_of_compromise"]

                        skill_type_norm = task_type.lower().replace(" ", "_")
                        if _should_retry(retry_check, skill_type_norm):
                            ioc_count = len(retry_check.get("iocs", []))
                            workflow.logger.info(f"IOC retry triggered: output has {ioc_count} IOCs, retrying once")

                            siem_event_data = task_data.get("input", {}).get("siem_event", {})
                            hints = _generate_retry_hints(retry_check, siem_event_data) if siem_event_data else ""
                            retry_prompt_text = _retry_assembler.build_retry_prompt(
                                original_prompt=current_prompt,
                                previous_output=json.dumps(retry_check),
                                skill_type=skill_type_norm,
                                missed_hints=hints,
                            )
                            # Re-generate code with retry context
                            retry_task = dict(task_data)
                            retry_task["input"] = dict(retry_task.get("input", {}))
                            retry_task["input"]["prompt"] = retry_prompt_text
                            retry_gen = await workflow.execute_activity(
                                generate_code,
                                retry_task,
                                schedule_to_close_timeout=timedelta(minutes=5)
                            )
                            retry_code = retry_gen["code"]

                            # Validate retry code
                            retry_val = await workflow.execute_activity(
                                validate_code,
                                retry_code,
                                schedule_to_close_timeout=timedelta(seconds=10)
                            )
                            if retry_val["is_safe"]:
                                retry_exec = await workflow.execute_activity(
                                    execute_code,
                                    retry_code,
                                    schedule_to_close_timeout=timedelta(minutes=2)
                                )
                                if retry_exec["status"] == "completed":
                                    retry_usage = retry_gen["usage"]
                                    total_tokens_input += retry_usage.get("prompt_tokens", 0)
                                    total_tokens_output += retry_usage.get("completion_tokens", 0)
                                    total_exec_ms += retry_gen["execution_ms"] + retry_exec["execution_ms"]
                                    stdout_str = retry_exec["stdout"]
                                    final_stdout = stdout_str
                                    final_code = retry_code
                                    code = retry_code
                                    workflow.logger.info("IOC retry succeeded — using retry output")
                except Exception as retry_err:
                    workflow.logger.info(f"IOC retry failed (non-fatal): {retry_err}")

            # --- CHECK FOR FOLLOW-UP ---
            if playbook_steps:
                if step_num < max_loop_steps:
                    previous_context = stdout_str[:2000]
                else:
                    break
            else:
                if step_num < MAX_STEPS:
                    followup = await workflow.execute_activity(
                        check_followup_needed,
                        {"stdout": stdout_str, "previous_prompt": current_prompt},
                        schedule_to_close_timeout=timedelta(seconds=10)
                    )

                    if not followup["needed"]:
                        break

                    previous_context = stdout_str[:2000]
                    current_prompt = followup["prompt"]

        # --- DERIVE SEVERITY from final output ---
        severity = None
        try:
            parsed_out = json.loads(final_stdout)
            risk_score = None
            if isinstance(parsed_out, dict):
                if "risk_score" in parsed_out:
                    risk_score = parsed_out["risk_score"]
                elif "statistics" in parsed_out and isinstance(parsed_out["statistics"], dict) and "risk_score" in parsed_out["statistics"]:
                    risk_score = parsed_out["statistics"]["risk_score"]

                if risk_score is not None:
                    try:
                        risk_score = int(risk_score)
                        if risk_score >= 80:
                            severity = "critical"
                        elif risk_score >= 60:
                            severity = "high"
                        elif risk_score >= 40:
                            severity = "medium"
                        elif risk_score >= 20:
                            severity = "low"
                        else:
                            severity = "informational"
                    except ValueError:
                        pass

                if not severity and "severity" in parsed_out:
                    sev_str = str(parsed_out["severity"]).lower()
                    if sev_str in ["critical", "high", "medium", "low", "informational"]:
                        severity = sev_str
        except Exception:
            pass

        if not severity:
            if task_type in ["incident_response", "threat_hunt", "ioc_scan"]:
                severity = "high"
            else:
                severity = "medium"

        await workflow.execute_activity(
            update_task_status,
            {
                "task_id": task_id,
                "status": "completed",
                "output": {"stdout": final_stdout, "code": final_code, "step_count": completed_steps},
                "tokens_input": total_tokens_input,
                "tokens_output": total_tokens_output,
                "execution_ms": total_exec_ms,
                "severity": severity
            },
            schedule_to_close_timeout=timedelta(seconds=10)
        )

        await workflow.execute_activity(
            log_audit,
            {
                "tenant_id": tenant_id,
                "action": "workflow_completed",
                "resource_type": "task",
                "resource_id": task_id,
                "details": {"status": "completed", "steps": completed_steps}
            },
            schedule_to_close_timeout=timedelta(seconds=10)
        )
        await workflow.execute_activity(
            log_audit_event,
            {
                "tenant_id": tenant_id,
                "event_type": "investigation_completed",
                "actor_type": "system",
                "resource_type": "task",
                "resource_id": task_id,
                "metadata": {"steps": completed_steps, "severity": severity}
            },
            schedule_to_close_timeout=timedelta(seconds=10)
        )

        # --- WRITE INVESTIGATION MEMORY ---
        try:
            await workflow.execute_activity(
                write_investigation_memory,
                {
                    "task_id": task_id,
                    "tenant_id": tenant_id,
                    "skill_used_id": skill_used_id,
                    "threat_type": task_type,
                    "final_output": parsed_out if 'parsed_out' in locals() else {}
                },
                schedule_to_close_timeout=timedelta(minutes=1)
            )
        except Exception as e:
            workflow.logger.info(f"Memory write failed non-fatally: {str(e)}")
            pass

        # --- ENTITY GRAPH + INVESTIGATION EMBEDDING (Sprint 1G) ---
        entity_result = {}
        investigation_id = None
        graph_write_result = {}
        try:
            # 1. Extract entities from investigation output
            entity_result = await workflow.execute_activity(
                extract_entities,
                {
                    "investigation_output": final_stdout,
                    "task_type": task_type,
                    "tenant_id": tenant_id,
                    "task_id": task_id
                },
                schedule_to_close_timeout=timedelta(minutes=2)
            )

            # Heartbeat lease after entity extraction
            try:
                await workflow.execute_activity(
                    heartbeat_lease_activity,
                    {"tenant_id": tenant_id, "task_id": task_id},
                    schedule_to_close_timeout=timedelta(seconds=5)
                )
            except Exception:
                pass

            # 2. Embed investigation + create investigations row
            inv_risk_score = previous_risk_score or 0
            inv_confidence = min(inv_risk_score / 100.0, 1.0) if inv_risk_score else 0.5
            verdict = _verdict_from_severity(severity)

            # Validate LLM risk score against independent heuristics (Security P1#18)
            try:
                siem_event_data = task_data.get("input", {}).get("siem_event", {})
                entity_list = entity_result.get("entities", []) if 'entity_result' in dir() else []
                validated = validate_risk_score(
                    llm_score=inv_risk_score,
                    alert_data=siem_event_data,
                    entities=entity_list,
                    output=final_stdout[:2000],
                    techniques=[],
                )
                if validated["score_overridden"]:
                    workflow.logger.info(f"Risk score overridden: {validated['override_reason']}")
                    inv_risk_score = validated["final_risk_score"]
                    severity = validated["final_severity"]
                    inv_confidence = min(inv_risk_score / 100.0, 1.0)
                    verdict = _verdict_from_severity(severity)
            except Exception as e:
                workflow.logger.info(f"Risk validation failed non-fatally: {e}")

            embed_result = await workflow.execute_activity(
                embed_investigation,
                {
                    "tenant_id": tenant_id,
                    "task_id": task_id,
                    "summary": final_stdout[:2000],
                    "verdict": verdict,
                    "risk_score": inv_risk_score,
                    "confidence": inv_confidence,
                    "attack_techniques": [],
                    "skill_id": skill_used_id,
                    "model_id": "fast",
                    "prompt_version": "1g",
                    "source": "production",
                    "task_type": task_type
                },
                schedule_to_close_timeout=timedelta(minutes=1)
            )

            investigation_id = embed_result.get("investigation_id")

            # 3. Write entity graph (entities, observations, edges)
            graph_write_result = {}
            if entity_result.get("entities") and investigation_id:
                graph_write_result = await workflow.execute_activity(
                    write_entity_graph,
                    {
                        "tenant_id": tenant_id,
                        "task_id": task_id,
                        "investigation_id": investigation_id,
                        "entities": entity_result["entities"],
                        "edges": entity_result.get("edges", []),
                        "confidence_source": injection_confidence,
                    },
                    schedule_to_close_timeout=timedelta(minutes=1)
                )
                await workflow.execute_activity(
                    log_audit_event,
                    {
                        "tenant_id": tenant_id,
                        "event_type": "entity_extracted",
                        "actor_type": "system",
                        "resource_type": "investigation",
                        "resource_id": investigation_id,
                        "metadata": {
                            "entity_count": len(entity_result["entities"]),
                            "edge_count": len(entity_result.get("edges", []))
                        }
                    },
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
        except Exception as e:
            workflow.logger.info(f"Entity graph pipeline failed non-fatally: {str(e)}")

        # --- CROSS-TENANT INTELLIGENCE (Sprint 1K) ---
        cross_tenant_hits = []
        graph_result_hashes = graph_write_result.get("entity_hashes", [])
        if graph_result_hashes and investigation_id:
            try:
                for ent_hash in graph_result_hashes[:20]:  # cap at 20 lookups
                    intel = await workflow.execute_activity(
                        get_entity_intelligence,
                        {"entity_hash": ent_hash, "tenant_id": tenant_id},
                        schedule_to_close_timeout=timedelta(seconds=30),
                    )
                    if intel.get("tenant_count", 1) >= 2:
                        cross_tenant_hits.append(intel)
                if cross_tenant_hits:
                    await workflow.execute_activity(
                        log_audit_event,
                        {
                            "tenant_id": tenant_id,
                            "event_type": "cross_tenant_hit",
                            "actor_type": "system",
                            "resource_type": "investigation",
                            "resource_id": investigation_id,
                            "metadata": {
                                "hit_count": len(cross_tenant_hits),
                                "entity_hashes": [h["entity_hash"] for h in cross_tenant_hits[:10]],
                                "max_tenant_count": max(h.get("tenant_count", 1) for h in cross_tenant_hits),
                            },
                        },
                        schedule_to_close_timeout=timedelta(seconds=10),
                    )
                    workflow.logger.info(
                        f"Cross-tenant: {len(cross_tenant_hits)} entities seen by multiple tenants"
                    )
            except Exception as e:
                workflow.logger.info(f"Cross-tenant intelligence failed non-fatally: {e}")

        # --- BLAST RADIUS (Sprint 1L) ---
        blast_radius_result = {}
        if investigation_id:
            try:
                blast_radius_result = await workflow.execute_activity(
                    compute_blast_radius,
                    {
                        "investigation_id": investigation_id,
                        "tenant_id": tenant_id,
                        "time_window_hours": 72,
                        "max_hops": 2,
                    },
                    schedule_to_close_timeout=timedelta(minutes=1)
                )
                workflow.logger.info(
                    f"Blast radius: {blast_radius_result.get('total_entities', 0)} entities, "
                    f"{len(blast_radius_result.get('affected_investigations', []))} related investigations"
                )
            except Exception as e:
                workflow.logger.info(f"Blast radius failed non-fatally: {e}")

        # --- FALSE POSITIVE ANALYSIS (Sprint 1L) ---
        fp_result = {}
        if investigation_id:
            try:
                fp_result = await workflow.execute_activity(
                    analyze_false_positive,
                    {
                        "investigation_id": investigation_id,
                        "tenant_id": tenant_id,
                        "summary": final_stdout[:2000],
                        "verdict": verdict,
                        "risk_score": inv_risk_score,
                        "entities": entity_result.get("entities", []),
                        "cross_tenant_hits": len(cross_tenant_hits),
                    },
                    schedule_to_close_timeout=timedelta(minutes=2)
                )
                workflow.logger.info(f"FP analysis: confidence={fp_result.get('confidence', 'N/A')}")
            except Exception as e:
                workflow.logger.info(f"FP analysis failed non-fatally: {e}")

        # --- INCIDENT REPORT (Sprint 1L) ---
        if investigation_id:
            try:
                report_result = await workflow.execute_activity(
                    generate_incident_report,
                    {
                        "investigation_id": investigation_id,
                        "tenant_id": tenant_id,
                        "summary": final_stdout[:2000],
                        "entities": entity_result.get("entities", []),
                        "edges": entity_result.get("edges", []),
                        "risk_score": inv_risk_score,
                        "verdict": verdict,
                        "attack_techniques": [],
                        "blast_radius": blast_radius_result,
                    },
                    schedule_to_close_timeout=timedelta(minutes=3)
                )
                workflow.logger.info(
                    f"Report generated: md={report_result.get('markdown_length', 0)} chars, "
                    f"pdf={report_result.get('pdf_size_bytes', 0)} bytes"
                )
            except Exception as e:
                workflow.logger.info(f"Report generation failed non-fatally: {e}")

        # --- SOAR RESPONSE AUTO-TRIGGER (Sprint 2B + Sprint 9B) ---
        if investigation_id:
            try:
                matching_playbooks = await workflow.execute_activity(
                    find_matching_playbooks,
                    {
                        "verdict": verdict,
                        "risk_score": inv_risk_score,
                        "tenant_id": tenant_id,
                    },
                    schedule_to_close_timeout=timedelta(seconds=15),
                )

                # Auto-trigger audit logging (Sprint 9B, Issue #51)
                if matching_playbooks:
                    try:
                        await workflow.execute_activity(
                            auto_trigger_playbooks,
                            {
                                "investigation_id": investigation_id,
                                "tenant_id": tenant_id,
                                "verdict": verdict,
                                "severity": severity,
                                "risk_score": inv_risk_score,
                                "task_id": task_id,
                                "task_type": task_type,
                                "matching_playbooks": matching_playbooks,
                            },
                            schedule_to_close_timeout=timedelta(seconds=15),
                        )
                    except Exception as e:
                        workflow.logger.info(f"Auto-trigger audit failed non-fatally: {e}")

                for pb in matching_playbooks:
                    try:
                        await workflow.execute_child_workflow(
                            ResponsePlaybookWorkflow.run,
                            {
                                "playbook_id": pb["id"],
                                "investigation_id": investigation_id,
                                "tenant_id": tenant_id,
                                "trigger_data": {
                                    "verdict": verdict,
                                    "risk_score": inv_risk_score,
                                    "task_id": task_id,
                                    "task_type": task_type,
                                },
                            },
                            id=f"response-{pb['id']}-{investigation_id}",
                            task_queue="hydra-tasks",
                        )
                        workflow.logger.info(f"Triggered playbook '{pb.get('name')}' for investigation {investigation_id}")
                    except Exception as e:
                        workflow.logger.info(f"Playbook '{pb.get('name')}' trigger failed non-fatally: {e}")
            except Exception as e:
                workflow.logger.info(f"Response auto-trigger failed non-fatally: {e}")

        # --- PII UNMASKING (Security P0#2) ---
        if pii_entity_map_key and final_stdout:
            try:
                final_stdout = await workflow.execute_activity(
                    unmask_response,
                    {"response_text": final_stdout, "entity_map_key": pii_entity_map_key},
                    schedule_to_close_timeout=timedelta(seconds=10)
                )
            except Exception as e:
                workflow.logger.info(f"PII unmasking failed non-fatally: {e}")

        return {"status": "completed", "steps": completed_steps}

    async def _fail_task(self, task_id: str, tenant_id: str, reason: str, tokens_input=0, tokens_output=0, exec_ms=0):
        await workflow.execute_activity(
            update_task_status,
            {
                "task_id": task_id,
                "status": "failed",
                "error_message": reason,
                "tokens_input": tokens_input,
                "tokens_output": tokens_output,
                "execution_ms": exec_ms
            },
            schedule_to_close_timeout=timedelta(seconds=10)
        )

        await workflow.execute_activity(
            log_audit,
            {
                "tenant_id": tenant_id,
                "action": "workflow_failed",
                "resource_type": "task",
                "resource_id": task_id,
                "details": {"error": reason}
            },
            schedule_to_close_timeout=timedelta(seconds=10)
        )
        return {"status": "failed"}
