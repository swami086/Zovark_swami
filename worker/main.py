import os
import asyncio
from temporalio.client import Client
from temporalio.worker import Worker
import psycopg2

from workflows import ExecuteTaskWorkflow
from activities import fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template

async def main():
    temporal_address = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
    print(f"Connecting to Temporal at {temporal_address}...")
    
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
        activities=[fetch_task, generate_code, validate_code, execute_code, update_task_status, log_audit, record_usage, save_investigation_step, check_followup_needed, generate_followup_code, check_requires_approval, create_approval_request, update_approval_request, retrieve_skill, write_investigation_memory, fill_skill_parameters, render_skill_template],
    )
    print("Starting Hydra Python Worker on hydra-tasks queue...")
    await worker.run()

if __name__ == "__main__":
    asyncio.run(main())
