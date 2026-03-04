import os
import asyncio
import socket
import random
import string
from temporalio.client import Client
from temporalio.worker import Worker
import psycopg2

from workflows import ExecuteTaskWorkflow
from activities import fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template, check_rate_limit_activity, decrement_active_activity

# Worker identity — read from env (K8s pod name) or generate
def _generate_worker_id():
    hostname = socket.gethostname()
    pid = os.getpid()
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{hostname}-{pid}-{rand}"

WORKER_ID = os.environ.get("WORKER_ID") or _generate_worker_id()

async def main():
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
        workflows=[ExecuteTaskWorkflow],
        activities=[fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template, check_rate_limit_activity, decrement_active_activity],
    )
    print(f"Worker {WORKER_ID} starting on task queue hydra-tasks")
    await worker.run()

if __name__ == "__main__":
    asyncio.run(main())
