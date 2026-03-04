import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Server, Database, Cpu, Radio, Shield, RefreshCw } from 'lucide-react';

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
    const [health, setHealth] = useState<HealthData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

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

                    {/* Version */}
                    <div className="text-center text-xs text-slate-600 pt-4">
                        HYDRA v{health.version} • Build {new Date().toISOString().slice(0, 10)}
                    </div>
                </>
            )}
        </div>
    );
};

export default Settings;
