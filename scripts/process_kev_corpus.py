#!/usr/bin/env python3
"""Kickoff script for CISA KEV corpus processing.

Submits a KEVProcessingWorkflow to Temporal that batch-processes
all unprocessed KEV entries into embeddings for similarity search.

Usage:
    python scripts/process_kev_corpus.py [--tenant-id TENANT_ID] [--batch-size N]

Prerequisites:
    - Temporal server running
    - KEV data already loaded via BootstrapCorpusWorkflow
    - Embedding server (TEI) running
"""
import argparse
import asyncio
import sys

from temporalio.client import Client


async def main():
    parser = argparse.ArgumentParser(description="Process CISA KEV corpus into embeddings")
    parser.add_argument("--tenant-id", default="hydra-dev", help="Tenant ID (default: hydra-dev)")
    parser.add_argument("--batch-size", type=int, default=50, help="Entries per batch (default: 50)")
    parser.add_argument("--max-batches", type=int, default=31, help="Max batches (default: 31)")
    parser.add_argument("--temporal-address", default="localhost:7233", help="Temporal address")
    args = parser.parse_args()

    print(f"Connecting to Temporal at {args.temporal_address}...")
    client = await Client.connect(args.temporal_address)

    print(f"Submitting KEVProcessingWorkflow (tenant={args.tenant_id}, batch_size={args.batch_size})...")
    handle = await client.start_workflow(
        "KEVProcessingWorkflow",
        {
            "tenant_id": args.tenant_id,
            "batch_size": args.batch_size,
            "max_batches": args.max_batches,
        },
        id=f"kev-processing-{args.tenant_id}",
        task_queue="hydra-tasks",
    )

    print(f"Workflow started: {handle.id}")
    print(f"Run ID: {handle.result_run_id}")
    print("Waiting for completion (this may take hours for full corpus)...")

    result = await handle.result()
    print(f"\nResults:")
    print(f"  Processed: {result.get('total_processed', 0)}")
    print(f"  Embeddings: {result.get('total_embeddings', 0)}")
    print(f"  Entities: {result.get('total_entities', 0)}")
    print(f"  Batches: {result.get('batches_run', 0)}")


if __name__ == "__main__":
    asyncio.run(main())
