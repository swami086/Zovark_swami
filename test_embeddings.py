import os
import requests
import psycopg2

DB_URL = "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
LITELLM_URL = "http://litellm:4000/v1/embeddings"
API_KEY = "sk-hydra-dev-2026"

def get_embedding(text):
    print(f"Generating embedding for: '{text}'...")
    response = requests.post(
        LITELLM_URL,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": "embed",
            "input": text
        }
    )
    if not response.ok:
        raise Exception(f"LiteLLM Error: {response.text}")
    data = response.json()
    return data['data'][0]['embedding']

def main():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    
    # 1. Ensure we have a tenant
    cur.execute("SELECT id FROM tenants LIMIT 1")
    tenant_id = cur.fetchone()[0]
    
    # 2. Generate embedding for memory
    memory_text = "sandbox execution completed successfully"
    memory_vector = get_embedding(memory_text)
    
    # 3. Insert into memory episodic
    print("Inserting memory into agent_memory_episodic table...")
    cur.execute(
        """
        INSERT INTO agent_memory_episodic (tenant_id, content, embedding)
        VALUES (%s, %s, %s::vector)
        RETURNING id
        """,
        (tenant_id, memory_text, memory_vector)
    )
    memory_id = cur.fetchone()[0]
    conn.commit()
    print(f"Inserted memory ID: {memory_id}")
    
    # 4. Generate query embedding
    query_text = "sandbox completed"
    query_vector = get_embedding(query_text)
    
    # 5. Semantic similarity search
    print("Performing semantic similarity search...")
    cur.execute(
        """
        SELECT id, content, 1 - (embedding <=> %s::vector) as similarity
        FROM agent_memory_episodic
        WHERE tenant_id = %s
        ORDER BY embedding <=> %s::vector
        LIMIT 3
        """,
        (query_vector, tenant_id, query_vector)
    )
    results = cur.fetchall()
    
    print("\n--- Similarity Search Results ---")
    for row in results:
        print(f"ID: {row[0]} | Score: {row[2]:.4f} | Content: {row[1]}")
        
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
