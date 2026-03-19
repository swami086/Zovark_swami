import os
import json
from typing import Optional

SIMILARITY_THRESHOLD = 0.85
LOOKBACK_HOURS = 24


def extract_behavioral_fingerprint(alert: dict) -> str:
    parts = [
        alert.get('rule_name', ''),
        alert.get('task_type', alert.get('rule_name', '')),
        alert.get('raw_log', '')[:500],
    ]
    return ' '.join(p for p in parts if p)


def check_semantic_dedup(alert: dict, db_conn) -> Optional[str]:
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return None

    model_path = os.environ.get('EMBEDDING_MODEL_PATH', '/app/models/all-MiniLM-L6-v2')
    try:
        model = SentenceTransformer(model_path)
    except Exception:
        return None

    fingerprint = extract_behavioral_fingerprint(alert)
    embedding = model.encode(fingerprint).tolist()

    cur = db_conn.cursor()
    cur.execute(
        """SELECT task_id, 1 - (embedding <=> %s::vector) AS similarity
           FROM investigation_fingerprints
           WHERE created_at > NOW() - make_interval(hours => %s)
           ORDER BY embedding <=> %s::vector
           LIMIT 1""",
        (embedding, LOOKBACK_HOURS, embedding)
    )
    row = cur.fetchone()
    cur.close()

    if row and row[1] >= SIMILARITY_THRESHOLD:
        return row[0]
    return None


def store_fingerprint(alert: dict, task_id: str, db_conn):
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return

    model_path = os.environ.get('EMBEDDING_MODEL_PATH', '/app/models/all-MiniLM-L6-v2')
    try:
        model = SentenceTransformer(model_path)
    except Exception:
        return

    fingerprint = extract_behavioral_fingerprint(alert)
    embedding = model.encode(fingerprint).tolist()

    cur = db_conn.cursor()
    cur.execute(
        """INSERT INTO investigation_fingerprints (task_id, fingerprint_text, embedding)
           VALUES (%s, %s, %s::vector)""",
        (task_id, fingerprint, embedding)
    )
    db_conn.commit()
    cur.close()
