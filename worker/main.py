import os
import asyncio
import socket
import random
import string
from temporalio.client import Client
from temporalio.worker import Worker
import psycopg2

from workflows import ExecuteTaskWorkflow
from activities import fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, log_audit_event, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template, check_rate_limit_activity, decrement_active_activity, heartbeat_lease_activity
from entity_graph import extract_entities, write_entity_graph, embed_investigation
from bootstrap.activities import load_mitre_techniques, load_cisa_kev, generate_synthetic_investigation, process_bootstrap_entity, list_techniques
from bootstrap.workflow import BootstrapCorpusWorkflow
from intelligence.blast_radius import compute_blast_radius
from intelligence.fp_analyzer import analyze_false_positive
from intelligence.cross_tenant import refresh_cross_tenant_intel, get_entity_intelligence, compute_threat_score
from intelligence.cross_tenant_workflow import CrossTenantRefreshWorkflow, _list_multi_tenant_entities
from skills.deobfuscation import run_deobfuscation
from reporting.incident_report import generate_incident_report
from detection.pattern_miner import mine_attack_patterns
from detection.sigma_generator import generate_sigma_rule
from detection.rule_validator import validate_sigma_rule
from detection.workflow import DetectionGenerationWorkflow, _list_candidates_for_generation
from prompt_init import init_prompts

# Worker identity — read from env (K8s pod name) or generate
def _generate_worker_id():
    hostname = socket.gethostname()
    pid = os.getpid()
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{hostname}-{pid}-{rand}"

WORKER_ID = os.environ.get("WORKER_ID") or _generate_worker_id()

async def main():
    # Initialize prompt registry at startup
    init_prompts()

    temporal_address = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
    print(f"Worker {WORKER_ID} connecting to Temporal at {temporal_address}...")
    
    # Retry connecting to Temporal since it might take a moment to be ready
    for _ in range(10):
        try:
            client = await Client.connect(temporal_address)
            break
        except Exception as e:
            print(f"Failed to connect to temporal: {e}, retrying in 5 seconds...")
            await asyncio.sleep(5)
    else:
        raise Exception("Could not connect to Temporal frontend")
        
    worker = Worker(
        client,
        task_queue="hydra-tasks",
        workflows=[ExecuteTaskWorkflow, BootstrapCorpusWorkflow, CrossTenantRefreshWorkflow, DetectionGenerationWorkflow],
        activities=[fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, log_audit_event, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template, check_rate_limit_activity, decrement_active_activity, heartbeat_lease_activity, extract_entities, write_entity_graph, embed_investigation, load_mitre_techniques, load_cisa_kev, generate_synthetic_investigation, process_bootstrap_entity, list_techniques, compute_blast_radius, analyze_false_positive, run_deobfuscation, generate_incident_report, refresh_cross_tenant_intel, get_entity_intelligence, compute_threat_score, _list_multi_tenant_entities, mine_attack_patterns, generate_sigma_rule, validate_sigma_rule, _list_candidates_for_generation],
    )
    print(f"Worker {WORKER_ID} starting on task queue hydra-tasks")
    await worker.run()

if __name__ == "__main__":
    asyncio.run(main())
