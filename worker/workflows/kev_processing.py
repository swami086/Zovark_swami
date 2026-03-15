"""CISA KEV corpus processing workflow.

Batch-processes KEV entries into embeddings for similarity search:
1. Generates synthetic alert from KEV data
2. Extracts entities (CVE, vendor, product)
3. Generates 768-dim embedding via TEI
4. Stores for similarity search

Rate limit: 1 batch/hour, ~31 hours total for 1,536 entries
"""
import os
import json
import logging
from datetime import timedelta

from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    import httpx
    from database.pool_manager import pooled_connection

logger = logging.getLogger(__name__)

TEI_URL = os.environ.get("TEI_URL", "http://embedding-server:80")


@activity.defn
async def fetch_unprocessed_kev_entries(params: dict) -> dict:
    """Fetch a batch of unprocessed KEV entries from bootstrap_corpus.

    Returns: {entries: [{id, source_id, title, description}], count: int}
    """
    batch_size = params.get("batch_size", 50)

    with pooled_connection("background") as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, source_id, title, description
                FROM bootstrap_corpus
                WHERE source = 'cisa'
                  AND (status IS NULL OR status = 'pending')
                  AND processed_at IS NULL
                ORDER BY created_at ASC
                LIMIT %s
            """, (batch_size,))
            entries = [dict(r) for r in cur.fetchall()]
            for e in entries:
                e['id'] = str(e['id'])

    return {'entries': entries, 'count': len(entries)}


@activity.defn
async def process_kev_entry(params: dict) -> dict:
    """Process a single KEV entry: generate alert, extract entities, embed.

    Returns: {source_id, embedding_created, entities_extracted}
    """
    from bootstrap.kev_alert_generator import generate_kev_alert

    entry = params.get("entry", {})
    tenant_id = params.get("tenant_id")
    entry_id = entry.get("id")
    source_id = entry.get("source_id", "")
    title = entry.get("title", "")
    description = entry.get("description", "")

    # Step 1: Generate synthetic alert
    alert_data = generate_kev_alert({
        'cve_id': source_id,
        'vendor': title.split(':')[0].strip() if ':' in title else '',
        'product': title.split(':')[1].strip() if ':' in title else title,
        'name': title,
        'description': description,
    })

    # Step 2: Generate embedding
    embedding_created = False
    embedding_id = None
    try:
        embed_text = f"{source_id} {title} {description[:500]}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{TEI_URL}/embed",
                json={"inputs": embed_text},
            )
            if resp.status_code == 200:
                embedding = resp.json()
                if isinstance(embedding, list) and len(embedding) > 0:
                    vec = embedding[0] if isinstance(embedding[0], list) else embedding
                    # Store embedding
                    with pooled_connection("normal") as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO investigations
                                (id, tenant_id, summary, embedding, source, created_at)
                                VALUES (gen_random_uuid(), %s, %s, %s, 'cisa-kev-bootstrap', NOW())
                                RETURNING id
                            """, (tenant_id, f"KEV: {source_id} - {title}", vec))
                            row = cur.fetchone()
                            if row:
                                embedding_id = str(row[0])
                                embedding_created = True
    except Exception as e:
        logger.warning(f"Embedding failed for KEV {source_id}: {e}")

    # Step 3: Extract basic entities (CVE, vendor, product)
    entities = []
    if source_id.startswith('CVE-'):
        entities.append({'type': 'cve', 'value': source_id})
    if alert_data.get('vendor'):
        entities.append({'type': 'vendor', 'value': alert_data['vendor']})
    if alert_data.get('product'):
        entities.append({'type': 'product', 'value': alert_data['product']})

    # Step 4: Mark as processed
    with pooled_connection("normal") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE bootstrap_corpus
                SET status = 'completed',
                    processed_at = NOW(),
                    embedding_id = %s,
                    entity_count = %s
                WHERE id = %s
            """, (embedding_id, len(entities), entry_id))

    return {
        'source_id': source_id,
        'embedding_created': embedding_created,
        'entities_extracted': len(entities),
    }


@workflow.defn
class KEVProcessingWorkflow:
    """Batch-process CISA KEV entries into embeddings.

    Processes entries in batches of 50, with rate limiting
    to avoid overwhelming the embedding server.
    """

    @workflow.run
    async def run(self, params: dict) -> dict:
        tenant_id = params.get("tenant_id")
        batch_size = params.get("batch_size", 50)
        max_batches = params.get("max_batches", 31)  # ~1536 / 50

        total_processed = 0
        total_embeddings = 0
        total_entities = 0
        batches_run = 0

        for batch_num in range(max_batches):
            # Fetch next batch
            batch_result = await workflow.execute_activity(
                fetch_unprocessed_kev_entries,
                {"batch_size": batch_size},
                start_to_close_timeout=timedelta(minutes=2),
            )

            entries = batch_result.get("entries", [])
            if not entries:
                break  # No more unprocessed entries

            # Process each entry in the batch
            for entry in entries:
                try:
                    result = await workflow.execute_activity(
                        process_kev_entry,
                        {"entry": entry, "tenant_id": tenant_id},
                        start_to_close_timeout=timedelta(minutes=3),
                    )
                    total_processed += 1
                    if result.get("embedding_created"):
                        total_embeddings += 1
                    total_entities += result.get("entities_extracted", 0)
                except Exception as e:
                    logger.warning(f"KEV entry {entry.get('source_id')} failed: {e}")

            batches_run += 1

            # Rate limit: wait between batches (skip on last)
            if batch_num < max_batches - 1 and entries:
                await workflow.sleep(timedelta(seconds=30))

        return {
            "total_processed": total_processed,
            "total_embeddings": total_embeddings,
            "total_entities": total_entities,
            "batches_run": batches_run,
        }
