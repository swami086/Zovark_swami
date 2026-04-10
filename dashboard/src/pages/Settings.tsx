import { useCallback, useEffect, useState } from 'react';
import { Settings as SettingsIcon, Server, Database, Cpu, Radio, Shield, RefreshCw, KeyRound, Copy, Trash2 } from 'lucide-react';
import { getUser, listMcpKeys, createMcpKey, revokeMcpKey, type McpKeyRow } from '../api/client';

interface HealthData {
    status: string;
    version: string;
    mode: string;
    llm_provider: string;
    llm_model: string;
    embedding_provider: string;
    database: string;
    services: {
        api: boolean;
        db: boolean;
        litellm: boolean;
        embedding: boolean;
    };
}

const StatusDot = ({ ok }: { ok: boolean }) => (
    <span className={`inline-block w-2.5 h-2.5 rounded-full ${ok ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
);

const Settings = () => {
    const user = getUser();
    const [health, setHealth] = useState<HealthData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [mcpKeys, setMcpKeys] = useState<McpKeyRow[]>([]);
    const [mcpLoading, setMcpLoading] = useState(false);
    const [mcpName, setMcpName] = useState('workstation');
    const [newKeyOnce, setNewKeyOnce] = useState<string | null>(null);
    const [mcpErr, setMcpErr] = useState<string | null>(null);

    const loadMcpKeys = useCallback(async () => {
        if (user?.role !== 'admin') return;
        try {
            setMcpErr(null);
            setMcpLoading(true);
            const rows = await listMcpKeys();
            setMcpKeys(rows);
        } catch (e: unknown) {
            setMcpErr(e instanceof Error ? e.message : 'Failed to load MCP keys');
        } finally {
            setMcpLoading(false);
        }
    }, [user?.role]);

    useEffect(() => {
        void loadMcpKeys();
    }, [loadMcpKeys]);

    const loadHealth = async () => {
        try {
            setLoading(true);
            setError(null);
            const resp = await fetch('http://localhost:8090/health');
            if (!resp.ok) throw new Error('Health check failed');
            const data = await resp.json();
            setHealth(data);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { loadHealth(); }, []);

    if (loading && !health) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="flex items-center space-x-3">
                    <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                    <span className="text-slate-400">Checking platform health...</span>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white flex items-center space-x-3">
                        <SettingsIcon className="w-7 h-7 text-cyan-500" />
                        <span>Settings</span>
                    </h1>
                    <p className="text-slate-500 mt-1">Platform configuration and health monitoring</p>
                </div>
                <button
                    onClick={loadHealth}
                    className="flex items-center space-x-2 px-3 py-2 bg-slate-800/50 text-slate-400 border border-slate-700/50 rounded-lg hover:bg-slate-700/50 transition-colors"
                >
                    <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    <span className="text-sm">Refresh</span>
                </button>
            </div>

            {error && (
                <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-3 text-rose-400 text-sm">{error}</div>
            )}

            {health && (
                <>
                    {/* Deployment Info */}
                    <div>
                        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">Deployment Info</h2>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                                <div className="flex items-center space-x-2 mb-2">
                                    <Server className="w-4 h-4 text-cyan-400" />
                                    <span className="text-xs text-slate-500 uppercase tracking-wider font-medium">Mode</span>
                                </div>
                                <p className="text-white font-semibold">
                                    {health.mode === 'airgap' ? (
                                        <span className="flex items-center space-x-2">
                                            <Shield className="w-4 h-4 text-amber-400" />
                                            <span>Air-Gap</span>
                                        </span>
                                    ) : (
                                        'Cloud'
                                    )}
                                </p>
                            </div>

                            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                                <div className="flex items-center space-x-2 mb-2">
                                    <Cpu className="w-4 h-4 text-violet-400" />
                                    <span className="text-xs text-slate-500 uppercase tracking-wider font-medium">LLM Provider</span>
                                </div>
                                <p className="text-white font-semibold text-sm">{health.llm_provider}</p>
                                <p className="text-xs text-slate-500 mt-0.5 font-mono">{health.llm_model}</p>
                            </div>

                            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                                <div className="flex items-center space-x-2 mb-2">
                                    <Radio className="w-4 h-4 text-emerald-400" />
                                    <span className="text-xs text-slate-500 uppercase tracking-wider font-medium">Embeddings</span>
                                </div>
                                <p className="text-white font-semibold text-sm">{health.embedding_provider}</p>
                            </div>

                            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                                <div className="flex items-center space-x-2 mb-2">
                                    <Database className="w-4 h-4 text-amber-400" />
                                    <span className="text-xs text-slate-500 uppercase tracking-wider font-medium">Database</span>
                                </div>
                                <p className="text-white font-semibold text-sm">{health.database}</p>
                            </div>
                        </div>
                    </div>

                    {/* Platform Health */}
                    <div>
                        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">Platform Health</h2>
                        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl divide-y divide-slate-700/30">
                            {[
                                { name: 'API Gateway', key: 'api', desc: 'Go REST API on :8090' },
                                { name: 'Database', key: 'db', desc: 'PostgreSQL + pgvector' },
                                { name: 'LLM Gateway', key: 'litellm', desc: 'LiteLLM proxy on :4000' },
                                { name: 'Embedding Server', key: 'embedding', desc: 'HuggingFace TEI on :8081' },
                            ].map(svc => (
                                <div key={svc.key} className="flex items-center justify-between px-5 py-4">
                                    <div>
                                        <span className="text-white font-medium">{svc.name}</span>
                                        <span className="text-xs text-slate-500 ml-3">{svc.desc}</span>
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <StatusDot ok={health.services[svc.key as keyof typeof health.services]} />
                                        <span className={`text-xs font-medium ${health.services[svc.key as keyof typeof health.services] ? 'text-emerald-400' : 'text-rose-400'}`}>
                                            {health.services[svc.key as keyof typeof health.services] ? 'Healthy' : 'Down'}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {user?.role === 'admin' && (
                        <div>
                            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                <KeyRound className="w-4 h-4 text-amber-400" />
                                MCP API Keys
                            </h2>
                            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 space-y-4">
                                <p className="text-xs text-slate-500">
                                    Use with the Zovark MCP server: set environment variable{' '}
                                    <code className="text-amber-200/90 bg-slate-900/80 px-1 rounded">ZOVARK_MCP_API_KEY</code>
                                    to the secret shown once at creation. Keys are stored hashed server-side.
                                </p>
                                {mcpErr && (
                                    <div className="text-rose-400 text-sm">{mcpErr}</div>
                                )}
                                {newKeyOnce && (
                                    <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 space-y-2">
                                        <p className="text-amber-200 text-xs font-bold uppercase tracking-wider">Copy now — shown once</p>
                                        <code className="block text-xs text-amber-100 font-mono break-all">{newKeyOnce}</code>
                                        <button
                                            type="button"
                                            onClick={() => { void navigator.clipboard.writeText(newKeyOnce); }}
                                            className="inline-flex items-center gap-1 text-xs text-amber-300 hover:text-amber-200"
                                        >
                                            <Copy className="w-3 h-3" /> Copy
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => setNewKeyOnce(null)}
                                            className="block text-xs text-slate-500 hover:text-slate-400 mt-2"
                                        >
                                            Dismiss
                                        </button>
                                    </div>
                                )}
                                <div className="flex flex-wrap gap-2 items-end">
                                    <div>
                                        <label className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Name</label>
                                        <input
                                            value={mcpName}
                                            onChange={e => setMcpName(e.target.value)}
                                            className="bg-slate-900/60 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white w-48"
                                        />
                                    </div>
                                    <button
                                        type="button"
                                        disabled={mcpLoading || !mcpName.trim()}
                                        onClick={async () => {
                                            try {
                                                setMcpErr(null);
                                                const r = await createMcpKey(mcpName.trim());
                                                setNewKeyOnce(r.key);
                                                await loadMcpKeys();
                                            } catch (e: unknown) {
                                                setMcpErr(e instanceof Error ? e.message : 'Create failed');
                                            }
                                        }}
                                        className="px-4 py-2 rounded-lg bg-amber-600/30 border border-amber-500/40 text-amber-100 text-sm font-medium hover:bg-amber-600/40 disabled:opacity-50"
                                    >
                                        Generate key
                                    </button>
                                </div>
                                <div className="border-t border-slate-700/40 pt-3">
                                    <p className="text-xs text-slate-500 mb-2">Active keys</p>
                                    {mcpLoading ? (
                                        <p className="text-slate-500 text-sm">Loading…</p>
                                    ) : mcpKeys.length === 0 ? (
                                        <p className="text-slate-500 text-sm">No keys yet.</p>
                                    ) : (
                                        <ul className="space-y-2">
                                            {mcpKeys.map(k => (
                                                <li key={k.id} className="flex items-center justify-between text-sm text-slate-300 font-mono bg-slate-900/40 rounded-lg px-3 py-2">
                                                    <span>
                                                        {k.name}
                                                        {!k.active && <span className="text-slate-600 ml-2">(revoked)</span>}
                                                    </span>
                                                    {k.active && (
                                                        <button
                                                            type="button"
                                                            title="Revoke"
                                                            onClick={async () => {
                                                                if (!confirm(`Revoke MCP key "${k.name}"?`)) return;
                                                                try {
                                                                    await revokeMcpKey(k.id);
                                                                    await loadMcpKeys();
                                                                } catch (e: unknown) {
                                                                    setMcpErr(e instanceof Error ? e.message : 'Revoke failed');
                                                                }
                                                            }}
                                                            className="p-1.5 text-rose-400 hover:bg-rose-500/10 rounded"
                                                        >
                                                            <Trash2 className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                </li>
                                            ))}
                                        </ul>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Version */}
                    <div className="text-center text-xs text-slate-600 pt-4">
                        ZOVARK v{health.version} • Build {new Date().toISOString().slice(0, 10)}
                    </div>
                </>
            )}
        </div>
    );
};

export default Settings;
