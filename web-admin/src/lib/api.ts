const BASE_URL = import.meta.env.VITE_API_URL || window.location.origin;

interface LoginResponse {
  token: string;
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

interface ServiceHealth {
  name: string;
  status: "healthy" | "degraded" | "down";
  latency_ms?: number;
  details?: string;
}

interface SystemHealth {
  status: "healthy" | "degraded" | "down";
  services: ServiceHealth[];
  gpu_tier?: string;
  uptime_seconds?: number;
}

interface ConfigEntry {
  key: string;
  value: string;
  is_secret: boolean;
  updated_at: string;
  updated_by: string;
}

interface ConfigAuditEntry {
  id: string;
  key: string;
  old_value: string;
  new_value: string;
  changed_by: string;
  changed_at: string;
}

interface TaskResponse {
  id: string;
  task_type: string;
  status: string;
  output?: {
    verdict?: string;
    risk_score?: number;
    summary?: string;
    findings?: string[];
  };
}

interface DiagHTTPResult {
  url: string;
  status_code: number;
  latency_ms: number;
  tls_version?: string;
  tls_cipher?: string;
  tls_expiry?: string;
  error?: string;
}

interface DiagParseResult {
  parsed: boolean;
  format_detected?: string;
  fields_extracted?: number;
  normalized?: Record<string, unknown>;
  error?: string;
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(
      `API ${res.status}: ${body || res.statusText}`
    );
  }

  return res.json() as Promise<T>;
}

function authHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}

// --- Auth ---

export async function login(
  email: string,
  password: string
): Promise<LoginResponse> {
  return request<LoginResponse>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function breakglassLogin(
  password: string
): Promise<LoginResponse> {
  return request<LoginResponse>("/api/v1/admin/breakglass/login", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

// --- System Health ---

export async function getSystemHealth(
  token: string
): Promise<SystemHealth> {
  return request<SystemHealth>("/api/v1/admin/system/health", {
    headers: authHeaders(token),
  });
}

// --- Config ---

export async function getConfig(
  token: string
): Promise<ConfigEntry[]> {
  return request<ConfigEntry[]>("/api/v1/admin/config", {
    headers: authHeaders(token),
  });
}

export async function upsertConfig(
  token: string,
  key: string,
  value: string,
  isSecret: boolean
): Promise<void> {
  await request<unknown>("/api/v1/admin/config", {
    method: "PUT",
    headers: authHeaders(token),
    body: JSON.stringify({ key, value, is_secret: isSecret }),
  });
}

export async function getConfigAudit(
  token: string
): Promise<ConfigAuditEntry[]> {
  return request<ConfigAuditEntry[]>("/api/v1/admin/config/audit", {
    headers: authHeaders(token),
  });
}

// --- Bootstrap / Synthetic ---

export async function injectSynthetic(
  token: string
): Promise<{ task_ids: string[] }> {
  return request<{ task_ids: string[] }>(
    "/api/v1/admin/bootstrap/inject-synthetic?force=true",
    {
      method: "POST",
      headers: authHeaders(token),
    }
  );
}

// --- Tasks ---

export async function getTask(
  token: string,
  id: string
): Promise<TaskResponse> {
  return request<TaskResponse>(`/api/v1/tasks/${id}`, {
    headers: authHeaders(token),
  });
}

// --- Diagnostics ---

export async function diagHTTPCheck(
  token: string,
  url: string
): Promise<DiagHTTPResult> {
  return request<DiagHTTPResult>(
    "/api/v1/admin/diagnostics/http-check",
    {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ url }),
    }
  );
}

export async function diagParseTest(
  token: string,
  rawJson: string
): Promise<DiagParseResult> {
  return request<DiagParseResult>(
    "/api/v1/admin/diagnostics/parse-test",
    {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ raw: rawJson }),
    }
  );
}

// --- Types re-export for consumers ---

export type {
  LoginResponse,
  ServiceHealth,
  SystemHealth,
  ConfigEntry,
  ConfigAuditEntry,
  TaskResponse,
  DiagHTTPResult,
  DiagParseResult,
};
