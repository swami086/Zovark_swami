import crypto from "crypto";
import { query } from "./db.js";

export interface McpAuthContext {
  keyId: string;
  tenantId: string;
  tenantSlug: string;
}

/** Validates ZOVARK_MCP_API_KEY against mcp_api_keys; updates last_used_at. */
export async function requireMcpApiKey(): Promise<McpAuthContext> {
  const raw = process.env.ZOVARK_MCP_API_KEY?.trim();
  if (!raw) {
    const err = new Error(
      "ZOVARK_MCP_API_KEY is not set. Generate a key in Dashboard → Settings → MCP API Keys."
    );
    Object.assign(err, { code: "mcp_auth_config" });
    throw err;
  }
  const hash = crypto.createHash("sha256").update(raw, "utf8").digest("hex");
  const r = await query(
    `SELECT m.id::text, m.tenant_id::text, t.slug
     FROM mcp_api_keys m
     INNER JOIN tenants t ON t.id = m.tenant_id
     WHERE m.key_hash = $1 AND m.revoked_at IS NULL
     LIMIT 1`,
    [hash]
  );
  if (r.rows.length === 0) {
    const err = new Error("Invalid or revoked MCP API key");
    Object.assign(err, { code: "mcp_auth_invalid" });
    throw err;
  }
  const row = r.rows[0] as { id: string; tenant_id: string; slug: string };
  await query(`UPDATE mcp_api_keys SET last_used_at = NOW() WHERE id = $1::uuid`, [
    row.id,
  ]);
  return {
    keyId: row.id,
    tenantId: row.tenant_id,
    tenantSlug: row.slug,
  };
}

export type McpResourceAuthResult =
  | { ok: true; mode: "selftest" }
  | { ok: true; mode: "key"; ctx: McpAuthContext }
  | {
      ok: false;
      payload: {
        contents: Array<{ uri: string; mimeType: string; text: string }>;
      };
    };

/** Resolves MCP API key → tenant context for resources (self-test = unscoped dev). */
export async function resolveMcpResourceAuth(
  uri: string
): Promise<McpResourceAuthResult> {
  if (process.argv.includes("--test")) {
    return { ok: true, mode: "selftest" };
  }
  try {
    const ctx = await requireMcpApiKey();
    return { ok: true, mode: "key", ctx };
  } catch (e) {
    const err = e as Error;
    return {
      ok: false,
      payload: {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(
              { error: "mcp_auth_failed", message: err.message },
              null,
              2
            ),
          },
        ],
      },
    };
  }
}

/** @deprecated Use resolveMcpResourceAuth for tenant-scoped resources. */
export async function ensureMcpResourceAuth(
  uri: string
): Promise<{ contents: Array<{ uri: string; mimeType: string; text: string }> } | null> {
  const r = await resolveMcpResourceAuth(uri);
  if (!r.ok) return r.payload;
  return null;
}

export function mcpAuthErrorResponse(err: unknown) {
  const e = err as Error & { code?: string };
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            error: e.code || "mcp_auth_failed",
            message: e.message || String(err),
          },
          null,
          2
        ),
      },
    ],
    isError: true,
  };
}
