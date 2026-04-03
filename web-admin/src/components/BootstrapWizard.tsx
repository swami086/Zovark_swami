import { useState, useEffect, useCallback, useRef } from "react";
import {
  CheckCircle2,
  XCircle,
  Loader2,
  ArrowRight,
  Server,
  Plug,
  FlaskConical,
  RefreshCw,
  Shield,
  Globe,
  Lock,
  Clock,
} from "lucide-react";
import {
  getSystemHealth,
  diagHTTPCheck,
  injectSynthetic,
  getTask,
  upsertConfig,
} from "../lib/api";
import type { SystemHealth, TaskResponse, DiagHTTPResult } from "../lib/api";

interface BootstrapWizardProps {
  token: string;
  onComplete: () => void;
}

type Step = 1 | 2 | 3;

interface SyntheticAlert {
  id: string;
  label: string;
  status: "pending" | "running" | "completed" | "failed";
  verdict?: string;
  riskScore?: number;
}

export default function BootstrapWizard({
  token,
  onComplete,
}: BootstrapWizardProps) {
  const [step, setStep] = useState<Step>(1);

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top Bar */}
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-emerald-400" />
            <span className="text-sm font-semibold text-zinc-100">
              Zovark Bootstrap
            </span>
          </div>
          <StepIndicator current={step} />
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 flex items-start justify-center px-4 py-10">
        <div className="w-full max-w-4xl">
          {step === 1 && (
            <HealthCheckStep token={token} onNext={() => setStep(2)} />
          )}
          {step === 2 && (
            <SIEMHandshakeStep token={token} onNext={() => setStep(3)} />
          )}
          {step === 3 && (
            <ShadowModeStep
              token={token}
              onComplete={async () => {
                try {
                  await upsertConfig(
                    token,
                    "bootstrap.completed",
                    "true",
                    false
                  );
                } catch {
                  // best-effort
                }
                onComplete();
              }}
            />
          )}
        </div>
      </main>
    </div>
  );
}

// --- Step Indicator ---

function StepIndicator({ current }: { current: Step }) {
  const steps = [
    { n: 1, label: "Health Check", icon: Server },
    { n: 2, label: "SIEM Handshake", icon: Plug },
    { n: 3, label: "Shadow Mode", icon: FlaskConical },
  ] as const;

  return (
    <div className="flex items-center gap-2">
      {steps.map((s, i) => (
        <div key={s.n} className="flex items-center gap-2">
          {i > 0 && (
            <div
              className={`w-8 h-px ${
                current > s.n - 1 ? "bg-emerald-500" : "bg-zinc-700"
              }`}
            />
          )}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
              current === s.n
                ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                : current > s.n
                  ? "bg-zinc-800 text-zinc-400 border border-zinc-700"
                  : "bg-zinc-900 text-zinc-600 border border-zinc-800"
            }`}
          >
            <s.icon className="w-3 h-3" />
            {s.label}
          </div>
        </div>
      ))}
    </div>
  );
}

// --- Step 1: Health Check ---

function HealthCheckStep({
  token,
  onNext,
}: {
  token: string;
  onNext: () => void;
}) {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchHealth = useCallback(async () => {
    try {
      const data = await getSystemHealth(token);
      setHealth(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch health");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchHealth();
    intervalRef.current = setInterval(fetchHealth, 5000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchHealth]);

  const coreServices = ["api", "postgresql", "postgres", "redis", "temporal"];
  const coreHealthy =
    health?.services.filter(
      (s) =>
        coreServices.some((c) => s.name.toLowerCase().includes(c)) &&
        s.status === "healthy"
    ).length ?? 0;
  const coreReady = coreHealthy >= 4;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-zinc-100">System Health Check</h2>
        <p className="text-sm text-zinc-400 mt-1">
          Verifying all core services are operational before proceeding.
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {loading && !health ? (
        <div className="flex items-center gap-2 text-zinc-400 text-sm py-8">
          <Loader2 className="w-4 h-4 animate-spin" />
          Checking services...
        </div>
      ) : health ? (
        <>
          {/* Overall status */}
          <div className="flex items-center gap-3">
            <span
              className={`badge-${
                health.status === "healthy"
                  ? "green"
                  : health.status === "degraded"
                    ? "yellow"
                    : "red"
              }`}
            >
              {health.status === "healthy" ? (
                <CheckCircle2 className="w-3 h-3" />
              ) : (
                <XCircle className="w-3 h-3" />
              )}
              {health.status.toUpperCase()}
            </span>
            {health.gpu_tier && (
              <span className="badge-zinc">{health.gpu_tier}</span>
            )}
            <button
              onClick={fetchHealth}
              className="ml-auto text-zinc-500 hover:text-zinc-300 transition-colors"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>

          {/* Service cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {health.services.map((svc) => (
              <ServiceCard key={svc.name} service={svc} />
            ))}
          </div>
        </>
      ) : null}

      <div className="flex justify-end pt-4 border-t border-zinc-800">
        <button
          onClick={onNext}
          disabled={!coreReady}
          className="btn-primary flex items-center gap-2"
        >
          Next
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

function ServiceCard({
  service,
}: {
  service: { name: string; status: string; latency_ms?: number; details?: string };
}) {
  const isHealthy = service.status === "healthy";
  const isDegraded = service.status === "degraded";

  return (
    <div
      className={`card flex items-center gap-3 ${
        isHealthy
          ? "border-emerald-500/20"
          : isDegraded
            ? "border-yellow-500/20"
            : "border-red-500/20"
      }`}
    >
      <div
        className={`w-2 h-2 rounded-full flex-shrink-0 ${
          isHealthy
            ? "bg-emerald-400"
            : isDegraded
              ? "bg-yellow-400"
              : "bg-red-400"
        }`}
      />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-zinc-200 truncate">
          {service.name}
        </div>
        {service.details && (
          <div className="text-xs text-zinc-500 truncate">{service.details}</div>
        )}
      </div>
      {service.latency_ms !== undefined && (
        <span className="text-xs text-zinc-500 flex-shrink-0">
          {service.latency_ms}ms
        </span>
      )}
    </div>
  );
}

// --- Step 2: SIEM Handshake ---

function SIEMHandshakeStep({
  token,
  onNext,
}: {
  token: string;
  onNext: () => void;
}) {
  const [siemType, setSiemType] = useState("splunk");
  const [url, setUrl] = useState("");
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<DiagHTTPResult | null>(null);
  const [error, setError] = useState("");

  async function handleTest() {
    if (!url.trim()) return;
    setTesting(true);
    setResult(null);
    setError("");
    try {
      const res = await diagHTTPCheck(token, url.trim());
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connection test failed");
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-zinc-100">SIEM Handshake</h2>
        <p className="text-sm text-zinc-400 mt-1">
          Test connectivity to your SIEM platform before enabling alert ingestion.
        </p>
      </div>

      <div className="card space-y-4">
        <div>
          <label className="block text-xs font-medium text-zinc-400 mb-1.5">
            SIEM Platform
          </label>
          <select
            value={siemType}
            onChange={(e) => setSiemType(e.target.value)}
            className="input-field"
          >
            <option value="splunk">Splunk HEC</option>
            <option value="elastic">Elastic SIEM</option>
            <option value="webhook">Custom Webhook</option>
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-zinc-400 mb-1.5">
            {siemType === "splunk"
              ? "Splunk HEC Endpoint"
              : siemType === "elastic"
                ? "Elasticsearch URL"
                : "Webhook URL"}
          </label>
          <div className="flex gap-2">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={
                siemType === "splunk"
                  ? "https://splunk.corp:8088/services/collector"
                  : siemType === "elastic"
                    ? "https://elastic.corp:9200"
                    : "https://webhook.corp/ingest"
              }
              className="input-field flex-1"
            />
            <button
              onClick={handleTest}
              disabled={testing || !url.trim()}
              className="btn-primary flex items-center gap-2 whitespace-nowrap"
            >
              {testing ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Globe className="w-4 h-4" />
              )}
              Test Connection
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-3 pt-2 border-t border-zinc-800">
            <div className="flex items-center gap-2">
              {result.error ? (
                <>
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span className="text-sm text-red-400">
                    Connection failed: {result.error}
                  </span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span className="text-sm text-emerald-400">
                    Connection successful (HTTP {result.status_code})
                  </span>
                </>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="flex items-center gap-2 text-zinc-400">
                <Clock className="w-3 h-3" />
                Latency: {result.latency_ms}ms
              </div>
              {result.tls_version && (
                <div className="flex items-center gap-2 text-zinc-400">
                  <Lock className="w-3 h-3" />
                  TLS: {result.tls_version}
                </div>
              )}
              {result.tls_cipher && (
                <div className="flex items-center gap-2 text-zinc-400 col-span-2">
                  Cipher: {result.tls_cipher}
                </div>
              )}
              {result.tls_expiry && (
                <div className="flex items-center gap-2 text-zinc-400 col-span-2">
                  Certificate expires: {result.tls_expiry}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="flex justify-end pt-4 border-t border-zinc-800">
        <button
          onClick={onNext}
          className="btn-primary flex items-center gap-2"
        >
          Next
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// --- Step 3: Shadow Mode ---

function ShadowModeStep({
  token,
  onComplete,
}: {
  token: string;
  onComplete: () => void;
}) {
  const [injecting, setInjecting] = useState(false);
  const [alerts, setAlerts] = useState<SyntheticAlert[]>([]);
  const [error, setError] = useState("");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const allComplete = alerts.length > 0 && alerts.every((a) => a.status === "completed");
  const anyFailed = alerts.some((a) => a.status === "failed");

  async function handleInject() {
    setInjecting(true);
    setError("");
    setAlerts([]);
    try {
      const res = await injectSynthetic(token);
      const labels = ["Brute Force (SSH)", "Phishing (URL)", "Benign (System)"];
      const initial: SyntheticAlert[] = res.task_ids.map((id, i) => ({
        id,
        label: labels[i] ?? `Alert ${i + 1}`,
        status: "running",
      }));
      setAlerts(initial);

      // Start polling
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        const updated = await Promise.all(
          initial.map(async (a) => {
            try {
              const task: TaskResponse = await getTask(token, a.id);
              if (task.status === "completed") {
                return {
                  ...a,
                  status: "completed" as const,
                  verdict: task.output?.verdict,
                  riskScore: task.output?.risk_score,
                };
              }
              if (task.status === "failed") {
                return { ...a, status: "failed" as const };
              }
              return a;
            } catch {
              return a;
            }
          })
        );
        setAlerts(updated);

        if (updated.every((a) => a.status === "completed" || a.status === "failed")) {
          if (pollRef.current) clearInterval(pollRef.current);
        }
      }, 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to inject alerts");
    } finally {
      setInjecting(false);
    }
  }

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-zinc-100">Shadow Mode Verification</h2>
        <p className="text-sm text-zinc-400 mt-1">
          Inject synthetic alerts to verify the investigation pipeline is functioning correctly.
        </p>
      </div>

      {error && (
        <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {alerts.length === 0 && (
        <div className="card flex flex-col items-center gap-4 py-10">
          <FlaskConical className="w-10 h-10 text-zinc-600" />
          <p className="text-sm text-zinc-400 text-center max-w-sm">
            This will inject 3 synthetic alerts (brute force, phishing, benign) and verify
            the pipeline returns correct verdicts.
          </p>
          <button
            onClick={handleInject}
            disabled={injecting}
            className="btn-primary flex items-center gap-2"
          >
            {injecting ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <FlaskConical className="w-4 h-4" />
            )}
            Inject Synthetic Alerts
          </button>
        </div>
      )}

      {alerts.length > 0 && (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className={`card flex items-center gap-4 ${
                alert.status === "completed"
                  ? "border-emerald-500/20"
                  : alert.status === "failed"
                    ? "border-red-500/20"
                    : "border-zinc-800"
              }`}
            >
              {alert.status === "running" && (
                <Loader2 className="w-5 h-5 text-zinc-400 animate-spin flex-shrink-0" />
              )}
              {alert.status === "completed" && (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
              )}
              {alert.status === "failed" && (
                <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
              )}
              {alert.status === "pending" && (
                <div className="w-5 h-5 rounded-full border-2 border-zinc-700 flex-shrink-0" />
              )}

              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-zinc-200">
                  {alert.label}
                </div>
                <div className="text-xs text-zinc-500 font-mono truncate">
                  {alert.id}
                </div>
              </div>

              {alert.status === "completed" && (
                <div className="flex items-center gap-3 flex-shrink-0">
                  <span
                    className={`badge-${
                      alert.verdict === "benign" ? "green" : "red"
                    }`}
                  >
                    {alert.verdict}
                  </span>
                  {alert.riskScore !== undefined && (
                    <span className="text-xs text-zinc-400">
                      Risk: {alert.riskScore}
                    </span>
                  )}
                </div>
              )}

              {alert.status === "running" && (
                <span className="text-xs text-zinc-500 flex-shrink-0">
                  Investigating...
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {anyFailed && (
        <div className="p-3 rounded-md bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 text-sm">
          One or more alerts failed. You can retry or proceed anyway.
        </div>
      )}

      <div className="flex justify-end pt-4 border-t border-zinc-800">
        <button
          onClick={onComplete}
          disabled={!allComplete && !anyFailed}
          className="btn-primary flex items-center gap-2"
        >
          <Shield className="w-4 h-4" />
          Enter Zovark
        </button>
      </div>
    </div>
  );
}
