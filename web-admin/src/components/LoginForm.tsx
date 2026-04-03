import { useState } from "react";
import { Shield, KeyRound, AlertTriangle, Loader2 } from "lucide-react";
import { login, breakglassLogin } from "../lib/api";

interface LoginFormProps {
  onLogin: (token: string) => void;
}

export default function LoginForm({ onLogin }: LoginFormProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [breakglassPassword, setBreakglassPassword] = useState("");
  const [showBreakglass, setShowBreakglass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await login(email, password);
      onLogin(res.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleBreakglass(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await breakglassLogin(breakglassPassword);
      onLogin(res.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Break-glass login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-xl bg-emerald-500/10 border border-emerald-500/20 mb-4">
            <Shield className="w-8 h-8 text-emerald-400" />
          </div>
          <h1 className="text-2xl font-bold text-zinc-100 tracking-tight">
            Zovark Control Plane
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            v3.2 Admin Console
          </p>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mb-4 flex items-start gap-2 p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Standard Login */}
        {!showBreakglass && (
          <form onSubmit={handleLogin} className="card space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@test.local"
                required
                autoFocus
                className="input-field"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                required
                className="input-field"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : null}
              {loading ? "Authenticating..." : "Sign In"}
            </button>

            <div className="pt-2 border-t border-zinc-800 text-center">
              <button
                type="button"
                onClick={() => {
                  setShowBreakglass(true);
                  setError("");
                }}
                className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors inline-flex items-center gap-1"
              >
                <KeyRound className="w-3 h-3" />
                Break-Glass Access
              </button>
            </div>
          </form>
        )}

        {/* Break-Glass Login */}
        {showBreakglass && (
          <form onSubmit={handleBreakglass} className="card space-y-4">
            <div className="flex items-center gap-2 p-2 rounded-md bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 text-xs">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>
                Break-glass access is audited. Use only during emergencies.
              </span>
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Emergency Password
              </label>
              <input
                type="password"
                value={breakglassPassword}
                onChange={(e) => setBreakglassPassword(e.target.value)}
                placeholder="Break-glass password"
                required
                autoFocus
                className="input-field"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="btn-danger w-full flex items-center justify-center gap-2"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : null}
              {loading ? "Authenticating..." : "Emergency Access"}
            </button>

            <div className="text-center">
              <button
                type="button"
                onClick={() => {
                  setShowBreakglass(false);
                  setError("");
                }}
                className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                Back to standard login
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
