"""Semantic investigation search activity (Issue #33).

Primary path: SurrealDB `investigation_vec` cosine similarity plus keyword blend.
Falls back to PostgreSQL pg_trgm when Surreal returns no rows or embeddings are unavailable.
"""

import os
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
    return psycopg2.connect(db_url)


EMBED_URL = os.environ.get("TEI_URL", "http://embedding-server:80/embed")
ZOVARK_EMBED_URL = os.environ.get("ZOVARK_LLM_ENDPOINT", "http://zovark-inference:8080") + "/v1/embeddings"
ZOVARK_LLM_KEY = os.environ.get("ZOVARK_LLM_KEY", "zovark-llm-key-2026")


async def _get_embedding(text):
    """Get embedding vector for search query."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try LiteLLM embeddings endpoint first
            resp = await client.post(
                ZOVARK_EMBED_URL,
                headers={
                    "Authorization": f"Bearer {ZOVARK_LLM_KEY}",
                    "Content-Type": "application/json",
                },
                json={"model": "embed", "input": text},
            )
            resp.raise_for_status()
            data = resp.json()
            return data["data"][0]["embedding"]
    except Exception:
        pass

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                EMBED_URL,
                json={"inputs": text},
            )
            resp.raise_for_status()
            embeddings = resp.json()
            return embeddings[0] if embeddings else None
    except Exception:
        return None


@activity.defn
async def semantic_search(data: dict) -> dict:
    """Search investigations using semantic similarity + keyword matching.

    Input: {
        query: str,
        tenant_id: optional,
        limit: 10,
        semantic_weight: 0.7,
        keyword_weight: 0.3,
    }
    Returns: {
        results: [{investigation_id, summary_snippet, score, verdict, risk_score, match_type}],
        total: int,
        query: str,
    }
    """
    query = data.get("query", "")
    tenant_id = data.get("tenant_id")
    limit = data.get("limit", 10)
    semantic_weight = data.get("semantic_weight", 0.7)
    keyword_weight = data.get("keyword_weight", 0.3)

    if not query:
        return {"results": [], "total": 0, "query": query}

    # Get query embedding for semantic search
    query_embedding = await _get_embedding(query)

    conn = _get_db()
    try:
        results = []

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if query_embedding:
                from surreal_graph import semantic_search_surreal

                surreal_rows = await semantic_search_surreal(
                    tenant_id, query_embedding, query, limit, semantic_weight, keyword_weight
                )
                for r in surreal_rows:
                    results.append(
                        {
                            "investigation_id": r.get("investigation_id"),
                            "summary_snippet": r.get("summary_snippet", ""),
                            "score": r.get("score", 0),
                            "semantic_score": r.get("semantic_score", 0),
                            "keyword_score": r.get("keyword_score", 0),
                            "verdict": r.get("verdict"),
                            "risk_score": r.get("risk_score"),
                            "match_type": r.get("match_type", "surreal_vector"),
                            "created_at": r.get("created_at", ""),
                        }
                    )
            if not results:
                keyword_query = """
                    SELECT
                        id::text as investigation_id,
                        LEFT(summary, 300) as summary_snippet,
                        verdict,
                        risk_score,
                        confidence,
                        similarity(summary, %s) as keyword_score,
                        created_at
                    FROM investigations
                    WHERE summary IS NOT NULL
                      AND similarity(summary, %s) > 0.1
                """
                params = [query, query]

                if tenant_id:
                    keyword_query += " AND tenant_id = %s"
                    params.append(tenant_id)

                keyword_query += " ORDER BY similarity(summary, %s) DESC LIMIT %s"
                params.extend([query, limit])

                cur.execute(keyword_query, params)
                rows = cur.fetchall()

                for row in rows:
                    r = dict(row)
                    results.append({
                        "investigation_id": r["investigation_id"],
                        "summary_snippet": r.get("summary_snippet", ""),
                        "score": round(float(r.get("keyword_score", 0)), 4),
                        "semantic_score": 0.0,
                        "keyword_score": round(float(r.get("keyword_score", 0)), 4),
                        "verdict": r.get("verdict"),
                        "risk_score": r.get("risk_score"),
                        "match_type": "keyword_only",
                        "created_at": str(r.get("created_at", "")),
                    })

        return {
            "results": results,
            "total": len(results),
            "query": query,
        }

    finally:
        conn.close()
