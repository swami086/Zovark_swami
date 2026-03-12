import os
import asyncio
import socket
import random
import string
from temporalio.client import Client
from temporalio.worker import Worker

from workflows import ExecuteTaskWorkflow
from activities import fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, log_audit_event, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template, check_rate_limit_activity, decrement_active_activity, heartbeat_lease_activity, validate_generated_code, enrich_alert_with_memory
from entity_graph import extract_entities, write_entity_graph, embed_investigation
from bootstrap.activities import load_mitre_techniques, load_cisa_kev, generate_synthetic_investigation, process_bootstrap_entity, list_techniques
from bootstrap.workflow import BootstrapCorpusWorkflow
from intelligence.blast_radius import compute_blast_radius
from intelligence.fp_analyzer import analyze_false_positive
from intelligence.cross_tenant import refresh_cross_tenant_intel, get_entity_intelligence, compute_threat_score
from intelligence.cross_tenant_workflow import CrossTenantRefreshWorkflow, _list_multi_tenant_entities
from intelligence.stix_taxii import ingest_threat_feed, poll_taxii_server
from skills.deobfuscation import run_deobfuscation
from reporting.incident_report import generate_incident_report
from detection.pattern_miner import mine_attack_patterns
from detection.sigma_generator import generate_sigma_rule
from detection.rule_validator import validate_sigma_rule
from detection.workflow import DetectionGenerationWorkflow, _list_candidates_for_generation
from response.workflow import ResponsePlaybookWorkflow, load_playbook, create_response_execution, update_response_execution, execute_response_action, rollback_response_action, find_matching_playbooks
from response.auto_trigger import auto_trigger_playbooks
from finetuning.workflow import FineTuningPipelineWorkflow, export_finetuning_data, score_training_quality, run_model_evaluation, create_finetuning_job, update_finetuning_job
from finetuning.evaluation import compute_eval_metrics
from sre.workflow import SelfHealingWorkflow
from sre.monitor import scan_for_failures
from sre.diagnose import diagnose_failure
from sre.patcher import generate_patch
from sre.tester import test_patch
from sre.applier import apply_patch
from scheduler.workflow import ScheduledWorkflow, load_scheduled_workflows, update_schedule_last_run
from correlation.engine import correlate_alerts, create_incident
from correlation.workflow import AlertCorrelationWorkflow
from sla.monitor import check_sla_compliance
from training.trigger import check_retrain_needed
from search.semantic import semantic_search
from embedding.batch import batch_embed_entities
from embedding.versioning import check_embedding_version, re_embed_stale
from integrations.virustotal import enrich_ioc_virustotal
from integrations.abuseipdb import check_ip_reputation
from integrations.slack import send_slack_notification
from integrations.jira import create_jira_ticket
from integrations.teams import send_teams_notification
from integrations.email import send_email_notification
from integrations.servicenow import create_snow_incident
from prompt_init import init_prompts
import logger


# Worker identity — read from env (K8s pod name) or generate
def _generate_worker_id():
    hostname = socket.gethostname()
    pid = os.getpid()
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{hostname}-{pid}-{rand}"


WORKER_ID = os.environ.get("WORKER_ID") or _generate_worker_id()
os.environ["WORKER_ID"] = WORKER_ID  # Make available to logger module


async def main():
    # Initialize prompt registry at startup
    init_prompts()

    temporal_address = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
    logger.info("Connecting to Temporal", address=temporal_address)

    # Retry connecting to Temporal since it might take a moment to be ready
    for _ in range(10):
        try:
            client = await Client.connect(temporal_address)
            break
        except Exception as e:
            logger.warn("Temporal connection failed, retrying", error=str(e))
            await asyncio.sleep(5)
    else:
        raise Exception("Could not connect to Temporal frontend")

    worker = Worker(
        client,
        task_queue="hydra-tasks",
        workflows=[
            ExecuteTaskWorkflow, BootstrapCorpusWorkflow, CrossTenantRefreshWorkflow,
            DetectionGenerationWorkflow, ResponsePlaybookWorkflow, FineTuningPipelineWorkflow,
            SelfHealingWorkflow, ScheduledWorkflow, AlertCorrelationWorkflow,
        ],
        activities=[
            # Core investigation activities
            fetch_task, generate_code, validate_code, execute_code,
            update_task_status, log_audit, log_audit_event, record_usage,
            save_investigation_step, check_followup_needed, generate_followup_code,
            check_requires_approval, create_approval_request, update_approval_request,
            retrieve_skill, write_investigation_memory, fill_skill_parameters,
            render_skill_template, check_rate_limit_activity, decrement_active_activity,
            heartbeat_lease_activity, validate_generated_code, enrich_alert_with_memory,
            # Entity graph
            extract_entities, write_entity_graph, embed_investigation,
            # Bootstrap corpus
            load_mitre_techniques, load_cisa_kev, generate_synthetic_investigation,
            process_bootstrap_entity, list_techniques,
            # Intelligence
            compute_blast_radius, analyze_false_positive,
            refresh_cross_tenant_intel, get_entity_intelligence, compute_threat_score,
            _list_multi_tenant_entities,
            ingest_threat_feed, poll_taxii_server,
            # Skills
            run_deobfuscation,
            # Reporting
            generate_incident_report,
            # Detection engine
            mine_attack_patterns, generate_sigma_rule, validate_sigma_rule,
            _list_candidates_for_generation,
            # Response playbooks
            load_playbook, create_response_execution, update_response_execution,
            execute_response_action, rollback_response_action, find_matching_playbooks,
            auto_trigger_playbooks,
            # Fine-tuning pipeline
            export_finetuning_data, score_training_quality, run_model_evaluation,
            create_finetuning_job, update_finetuning_job,
            compute_eval_metrics,
            # SRE self-healing
            scan_for_failures, diagnose_failure, generate_patch, test_patch, apply_patch,
            # Scheduler (Sprint 9B)
            load_scheduled_workflows, update_schedule_last_run,
            # Correlation engine (Sprint 9B)
            correlate_alerts, create_incident,
            # SLA monitoring (Sprint 9B)
            check_sla_compliance,
            # Auto-retrain trigger (Sprint 9B)
            check_retrain_needed,
            # Semantic search (Sprint 9B)
            semantic_search,
            # Batch embedding + versioning (Sprint 9B)
            batch_embed_entities, check_embedding_version, re_embed_stale,
            # External integrations
            enrich_ioc_virustotal, check_ip_reputation,
            send_slack_notification, create_jira_ticket,
            send_teams_notification, send_email_notification, create_snow_incident,
        ],
    )
    logger.info("Worker starting", task_queue="hydra-tasks", workflows=9, activities=80)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
