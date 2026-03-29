const API_URL = process.env.ZOVARK_API_URL || "http://localhost:8090";

interface JwtCache {
  token: string;
  expiresAt: number;
  tenantSlug: string;
}

let cachedJwt: JwtCache | null = null;

export async function getJwt(
  tenantSlug: string = "zovark-dev"
): Promise<string> {
  if (
    cachedJwt &&
    cachedJwt.tenantSlug === tenantSlug &&
    Date.now() < cachedJwt.expiresAt
  ) {
    return cachedJwt.token;
  }

  const email = `mcp-agent@${tenantSlug}.zovark`;
  const password = "mcp-agent-2026!";

  // Try login first
  try {
    const loginResp = await fetch(`${API_URL}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (loginResp.ok) {
      const data = (await loginResp.json()) as { token: string };
      cachedJwt = {
        token: data.token,
        tenantSlug,
        expiresAt: Date.now() + 55 * 60 * 1000, // 55 min
      };
      return data.token;
    }
  } catch {
    // login failed, try register
  }

  // Register new user
  const regResp = await fetch(`${API_URL}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      password,
      display_name: "MCP Agent",
      tenant_slug: tenantSlug,
    }),
  });
  if (!regResp.ok) {
    const errText = await regResp.text();
    throw new Error(`Auth failed (register): ${regResp.status} ${errText}`);
  }

  // Login after register
  const loginResp = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!loginResp.ok) {
    const errText = await loginResp.text();
    throw new Error(`Auth failed (login): ${loginResp.status} ${errText}`);
  }
  const data = (await loginResp.json()) as { token: string };
  cachedJwt = {
    token: data.token,
    tenantSlug,
    expiresAt: Date.now() + 55 * 60 * 1000,
  };
  return data.token;
}

export async function apiGet(
  path: string,
  tenantSlug?: string
): Promise<unknown> {
  const token = await getJwt(tenantSlug);
  const resp = await fetch(`${API_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) {
    throw new Error(`API GET ${path}: ${resp.status} ${await resp.text()}`);
  }
  return resp.json();
}

export async function apiPost(
  path: string,
  body: unknown,
  tenantSlug?: string
): Promise<unknown> {
  const token = await getJwt(tenantSlug);
  const resp = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(`API POST ${path}: ${resp.status} ${await resp.text()}`);
  }
  return resp.json();
}

export async function apiHealthCheck(): Promise<boolean> {
  try {
    const resp = await fetch(`${API_URL}/health`, { signal: AbortSignal.timeout(5000) });
    return resp.ok;
  } catch {
    return false;
  }
}

export { API_URL };
