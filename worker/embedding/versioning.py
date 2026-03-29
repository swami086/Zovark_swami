"""Embedding versioning — track model version and re-embed stale vectors (Issue #36).

Tracks embedding model version in metadata. Flags and re-embeds stale
embeddings when the embedding model changes.
"""

import os
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


ZOVARK_LLM_ENDPOINT = os.environ.get("ZOVARK_LLM_ENDPOINT", "http://host.docker.internal:11434")
ZOVARK_LLM_KEY = os.environ.get("ZOVARK_LLM_KEY", "zovark-llm-key-2026")

# Current embedding model version — update when model changes
CURRENT_EMBED_MODEL = os.environ.get("ZOVARK_EMBED_MODEL", "nomic-embed-text-v1.5")
CURRENT_EMBED_VERSION = os.environ.get("ZOVARK_EMBED_VERSION", "1.5")
RE_EMBED_BATCH_SIZE = 100


@activity.defn
async def check_embedding_version(data: dict) -> dict:
    """Check for stale embeddings that need re-embedding.

    Input: {current_version: str, tenant_id: optional}
    Returns: {
        current_version: str, stale_count: int,
        total_embedded: int, needs_reembed: bool
    }
    """
    current_version = data.get("current_version", CURRENT_EMBED_VERSION)
    tenant_id = data.get("tenant_id")

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Count entities with embeddings
            total_query = "SELECT COUNT(*) as total FROM entities WHERE embedding IS NOT NULL"
            params = []
            if tenant_id:
                total_query += " AND tenant_id = %s"
                params.append(tenant_id)
            cur.execute(total_query, params)
            total_embedded = cur.fetchone()["total"]

            # Count stale embeddings (different version or no version metadata)
            # We use the metadata JSONB column if it exists, otherwise all are stale
            stale_query = """
                SELECT COUNT(*) as stale
                FROM entities
                WHERE embedding IS NOT NULL
                  AND (
                    metadata IS NULL
                    OR metadata->>'embed_version' IS NULL
                    OR metadata->>'embed_version' != %s
                  )
            """
            stale_params = [current_version]
            if tenant_id:
                stale_query += " AND tenant_id = %s"
                stale_params.append(tenant_id)

            try:
                cur.execute(stale_query, stale_params)
                stale_count = cur.fetchone()["stale"]
            except Exception:
                # metadata column might not have embed_version yet
                stale_count = total_embedded

        needs_reembed = stale_count > 0

        return {
            "current_version": current_version,
            "current_model": CURRENT_EMBED_MODEL,
            "stale_count": stale_count,
            "total_embedded": total_embedded,
            "needs_reembed": needs_reembed,
        }

    finally:
        conn.close()


@activity.defn
async def re_embed_stale(data: dict) -> dict:
    """Re-embed entities with outdated embedding versions.

    Input: {current_version: str, batch_size: 100, max_batches: 10, tenant_id: optional}
    Returns: {re_embedded: int, errors: int, batches_run: int}
    """
    current_version = data.get("current_version", CURRENT_EMBED_VERSION)
    batch_size = data.get("batch_size", RE_EMBED_BATCH_SIZE)
    max_batches = data.get("max_batches", 10)
    tenant_id = data.get("tenant_id")

    re_embedded = 0
    errors = 0
    batches_run = 0

    for batch_num in range(max_batches):
        conn = _get_db()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT id::text, value, type
                    FROM entities
                    WHERE embedding IS NOT NULL
                      AND (
                        metadata IS NULL
                        OR metadata->>'embed_version' IS NULL
                        OR metadata->>'embed_version' != %s
                      )
                """
                params = [current_version]
                if tenant_id:
                    query += " AND tenant_id = %s"
                    params.append(tenant_id)

                query += " LIMIT %s"
                params.append(batch_size)

                try:
                    cur.execute(query, params)
                    entities = [dict(r) for r in cur.fetchall()]
                except Exception:
                    entities = []
        finally:
            conn.close()

        if not entities:
            break

        batches_run += 1

        # Get new embeddings
        texts = [f"{e['type']}:{e['value']}" for e in entities]
        embeddings = await _batch_embed(texts)

        if not embeddings or len(embeddings) != len(entities):
            errors += 1
            continue

        # Update entities with new embeddings and version metadata
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                for entity, embedding in zip(entities, embeddings):
                    try:
                        cur.execute("""
                            UPDATE entities
                            SET embedding = %s::vector,
                                metadata = COALESCE(metadata, '{}'::jsonb) ||
                                    jsonb_build_object(
                                        'embed_version', %s,
                                        'embed_model', %s
                                    )
                            WHERE id = %s
                        """, (
                            str(embedding),
                            current_version,
                            CURRENT_EMBED_MODEL,
                            entity["id"],
                        ))
                        re_embedded += 1
                    except Exception as e:
                        errors += 1
                        print(f"re_embed_stale: entity {entity['id']} failed: {e}")
            conn.commit()
        finally:
            conn.close()

    return {
        "re_embedded": re_embedded,
        "errors": errors,
        "batches_run": batches_run,
        "current_version": current_version,
    }


async def _batch_embed(texts):
    """Get embeddings for a batch of texts via LiteLLM."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{ZOVARK_LLM_ENDPOINT}/v1/embeddings",
                headers={
                    "Authorization": f"Bearer {ZOVARK_LLM_KEY}",
                    "Content-Type": "application/json",
                },
                json={"model": "embed", "input": texts},
            )
            resp.raise_for_status()
            data = resp.json()
            return [item["embedding"] for item in data.get("data", [])]
    except Exception as e:
        print(f"re_embed: embedding API failed: {e}")
        return None
