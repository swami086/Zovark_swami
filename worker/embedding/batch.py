"""Batch entity embedding pipeline activity (Issue #34).

Queries entities without embeddings, batches them, and embeds via LiteLLM.
Processes in chunks of 100 to manage memory and API rate limits.
"""

import os
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


LITELLM_URL = os.environ.get("LITELLM_URL", "http://litellm:4000")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
BATCH_SIZE = 100


@activity.defn
async def batch_embed_entities(data: dict) -> dict:
    """Batch embed entities that are missing embeddings.

    Input: {batch_size: 100, tenant_id: optional, max_batches: 10}
    Returns: {
        total_processed: int, total_embedded: int,
        batches_run: int, errors: int
    }
    """
    batch_size = data.get("batch_size", BATCH_SIZE)
    tenant_id = data.get("tenant_id")
    max_batches = data.get("max_batches", 10)

    total_processed = 0
    total_embedded = 0
    batches_run = 0
    errors = 0

    for batch_num in range(max_batches):
        # Fetch entities without embeddings
        conn = _get_db()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT id::text, value, type
                    FROM entities
                    WHERE embedding IS NULL
                """
                params = []
                if tenant_id:
                    query += " AND tenant_id = %s"
                    params.append(tenant_id)

                query += " ORDER BY created_at LIMIT %s"
                params.append(batch_size)

                cur.execute(query, params)
                entities = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        if not entities:
            break

        batches_run += 1
        total_processed += len(entities)

        # Prepare texts for batch embedding
        texts = [f"{e['type']}:{e['value']}" for e in entities]

        # Get embeddings from LiteLLM
        embeddings = await _batch_embed(texts)

        if not embeddings or len(embeddings) != len(entities):
            errors += 1
            continue

        # Update entities with embeddings
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                for entity, embedding in zip(entities, embeddings):
                    try:
                        cur.execute("""
                            UPDATE entities
                            SET embedding = %s::vector
                            WHERE id = %s
                        """, (str(embedding), entity["id"]))
                        total_embedded += 1
                    except Exception as e:
                        errors += 1
                        print(f"batch_embed: entity {entity['id']} failed: {e}")
            conn.commit()
        finally:
            conn.close()

    return {
        "total_processed": total_processed,
        "total_embedded": total_embedded,
        "batches_run": batches_run,
        "errors": errors,
    }


async def _batch_embed(texts):
    """Get embeddings for a batch of texts via LiteLLM.

    Returns list of embedding vectors or None on failure.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{LITELLM_URL}/v1/embeddings",
                headers={
                    "Authorization": f"Bearer {LITELLM_KEY}",
                    "Content-Type": "application/json",
                },
                json={"model": "embed", "input": texts},
            )
            resp.raise_for_status()
            data = resp.json()
            return [item["embedding"] for item in data.get("data", [])]
    except Exception as e:
        print(f"batch_embed: embedding API failed: {e}")
        return None
