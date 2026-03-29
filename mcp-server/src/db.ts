import pg from "pg";

const DB_URL =
  process.env.ZOVARK_DB_URL ||
  "postgresql://zovark:hydra_dev_2026@localhost:5432/zovark";

let pool: pg.Pool | null = null;

export function getPool(): pg.Pool {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: DB_URL,
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
  }
  return pool;
}

export async function query(
  sql: string,
  params?: unknown[]
): Promise<pg.QueryResult> {
  const client = await getPool().connect();
  try {
    await client.query("SET statement_timeout = '10s'");
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

export async function testConnection(): Promise<boolean> {
  try {
    await query("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
