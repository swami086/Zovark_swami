import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Database, Plus, Copy, Check, Radio, AlertTriangle, ExternalLink, Zap } from 'lucide-react';
import { fetchLogSources, createLogSource, fetchSIEMAlerts, investigateAlert, getUser, type LogSource, type SIEMAlert } from '../api/client';

const sourceTypeLabels: Record<string, { label: string; color: string }> = {
    splunk: { label: 'Splunk', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
    elastic: { label: 'Elastic', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
    qradar: { label: 'QRadar', color: 'bg-violet-500/20 text-violet-400 border-violet-500/30' },
    syslog: { label: 'Syslog', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' },
    webhook_generic: { label: 'Generic', color: 'bg-slate-500/20 text-slate-400 border-slate-500/30' },
};

const severityColors: Record<string, string> = {
    critical: 'text-rose-400',
    high: 'text-orange-400',
    medium: 'text-amber-400',
    low: 'text-emerald-400',
};

const statusColors: Record<string, string> = {
    new: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    investigating: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    resolved: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    ignored: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
};

const CopyButton = ({ text }: { text: string }) => {
    const [copied, setCopied] = useState(false);
    const handleCopy = () => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };
    return (
        <button onClick={handleCopy} className="p-1 hover:bg-slate-700/50 rounded transition-colors" title="Copy webhook URL">
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
        </button>
    );
};

const LogSources = () => {
    const user = getUser();
    const isAdmin = user?.role === 'admin';

    const [sources, setSources] = useState<LogSource[]>([]);
    const [alerts, setAlerts] = useState<SIEMAlert[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [statusFilter, setStatusFilter] = useState<string>('');

    // Create form
    const [formName, setFormName] = useState('');
    const [formType, setFormType] = useState('splunk');
    const [formSecret, setFormSecret] = useState('');
    const [formAutoInvestigate, setFormAutoInvestigate] = useState(true);
    const [formDefaultTaskType, setFormDefaultTaskType] = useState('threat_hunt');
    const [createdWebhookUrl, setCreatedWebhookUrl] = useState('');

    const loadData = async () => {
        try {
            setLoading(true);
            const [srcData, alertData] = await Promise.all([
                fetchLogSources(),
                fetchSIEMAlerts(statusFilter || undefined),
            ]);
            setSources(srcData.sources || []);
            setAlerts(alertData.alerts || []);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { loadData(); }, [statusFilter]);

    const handleCreate = async () => {
        try {
            const config: Record<string, any> = {
                auto_investigate: formAutoInvestigate,
                default_task_type: formDefaultTaskType,
            };
            if (formSecret) config.webhook_secret = formSecret;

            const result = await createLogSource({
                name: formName,
                source_type: formType,
                connection_config: config,
            });
            setCreatedWebhookUrl(`${window.location.origin}${result.webhook_url}`);
            setFormName('');
            setFormSecret('');
            loadData();
        } catch (e: any) {
            setError(e.message);
        }
    };

    const handleInvestigate = async (alertId: string) => {
        try {
            await investigateAlert(alertId);
            loadData();
        } catch (e: any) {
            setError(e.message);
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="flex items-center space-x-3">
                    <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                    <span className="text-slate-400">Loading log sources...</span>
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
                        <Database className="w-7 h-7 text-cyan-500" />
                        <span>Log Sources</span>
                    </h1>
                    <p className="text-slate-500 mt-1">Connect your SIEM to auto-trigger investigations from alerts</p>
                </div>
                {isAdmin && (
                    <button
                        onClick={() => { setShowCreateModal(true); setCreatedWebhookUrl(''); }}
                        className="flex items-center space-x-2 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-colors"
                    >
                        <Plus className="w-4 h-4" />
                        <span className="font-medium text-sm">Connect New Source</span>
                    </button>
                )}
            </div>

            {error && (
                <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-3 text-rose-400 text-sm">{error}</div>
            )}

            {/* Source Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {sources.length === 0 ? (
                    <div className="col-span-2 text-center py-12 text-slate-500">
                        <Database className="w-12 h-12 mx-auto mb-3 opacity-30" />
                        <p>No log sources configured</p>
                        {isAdmin && <p className="text-sm mt-1">Click "Connect New Source" to get started</p>}
                    </div>
                ) : (
                    sources.map(source => {
                        const typeInfo = sourceTypeLabels[source.source_type] || sourceTypeLabels.webhook_generic;
                        const webhookFullUrl = `${window.location.protocol}//${window.location.hostname}:8090${source.webhook_url}`;
                        return (
                            <div key={source.id} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 hover:border-cyan-500/20 transition-all">
                                <div className="flex items-start justify-between mb-3">
                                    <div className="flex items-center space-x-3">
                                        <div className={`w-2 h-2 rounded-full ${source.is_active ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
                                        <h3 className="text-white font-semibold">{source.name}</h3>
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border ${typeInfo.color}`}>
                                            {typeInfo.label}
                                        </span>
                                    </div>
                                </div>

                                <div className="flex items-center space-x-2 mb-3 bg-slate-900/50 rounded-lg px-3 py-2">
                                    <code className="text-xs text-slate-400 flex-1 truncate font-mono">{webhookFullUrl}</code>
                                    <CopyButton text={webhookFullUrl} />
                                </div>

                                <div className="flex items-center space-x-4 text-xs text-slate-500">
                                    <span className="flex items-center space-x-1">
                                        <Radio className="w-3 h-3" />
                                        <span>{source.event_count.toLocaleString()} events</span>
                                    </span>
                                    {source.last_event_at && (
                                        <span>Last: {new Date(source.last_event_at).toLocaleString()}</span>
                                    )}
                                    {source.connection_config?.auto_investigate && (
                                        <span className="flex items-center space-x-1 text-cyan-400">
                                            <Zap className="w-3 h-3" />
                                            <span>Auto-investigate</span>
                                        </span>
                                    )}
                                </div>
                            </div>
                        );
                    })
                )}
            </div>

            {/* Create Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
                    <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-lg space-y-4">
                        <h2 className="text-lg font-bold text-white">Connect New Log Source</h2>

                        {createdWebhookUrl ? (
                            <div className="space-y-3">
                                <p className="text-emerald-400 font-medium">✓ Source created successfully!</p>
                                <p className="text-slate-400 text-sm">Add this URL as a webhook destination in your SIEM alert actions:</p>
                                <div className="flex items-center space-x-2 bg-slate-900/50 rounded-lg px-3 py-2">
                                    <code className="text-xs text-cyan-400 flex-1 break-all font-mono">{createdWebhookUrl}</code>
                                    <CopyButton text={createdWebhookUrl} />
                                </div>
                                <button onClick={() => setShowCreateModal(false)} className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600 transition-colors text-sm font-medium">
                                    Done
                                </button>
                            </div>
                        ) : (
                            <>
                                <div>
                                    <label className="text-xs text-slate-400 uppercase tracking-wider font-medium">Name</label>
                                    <input type="text" value={formName} onChange={e => setFormName(e.target.value)} placeholder="Production Splunk"
                                        className="w-full mt-1 bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50" />
                                </div>
                                <div>
                                    <label className="text-xs text-slate-400 uppercase tracking-wider font-medium">Type</label>
                                    <select value={formType} onChange={e => setFormType(e.target.value)}
                                        className="w-full mt-1 bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500/50">
                                        <option value="splunk">Splunk</option>
                                        <option value="elastic">Elastic</option>
                                        <option value="qradar">QRadar</option>
                                        <option value="syslog">Syslog</option>
                                        <option value="webhook_generic">Generic Webhook</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="text-xs text-slate-400 uppercase tracking-wider font-medium">Webhook Secret (optional)</label>
                                    <input type="text" value={formSecret} onChange={e => setFormSecret(e.target.value)} placeholder="HMAC-SHA256 secret"
                                        className="w-full mt-1 bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50" />
                                </div>
                                <div className="flex items-center space-x-3">
                                    <input type="checkbox" id="auto-investigate" checked={formAutoInvestigate} onChange={e => setFormAutoInvestigate(e.target.checked)}
                                        className="w-4 h-4 accent-cyan-500" />
                                    <label htmlFor="auto-investigate" className="text-sm text-slate-300">Auto-investigate incoming alerts</label>
                                </div>
                                <div>
                                    <label className="text-xs text-slate-400 uppercase tracking-wider font-medium">Default Task Type</label>
                                    <select value={formDefaultTaskType} onChange={e => setFormDefaultTaskType(e.target.value)}
                                        className="w-full mt-1 bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500/50">
                                        <option value="log_analysis">Log Analysis</option>
                                        <option value="threat_hunt">Threat Hunt</option>
                                        <option value="incident_response">Incident Response</option>
                                        <option value="code_audit">Code Audit</option>
                                        <option value="ioc_scan">IOC Scan</option>
                                    </select>
                                </div>
                                <div className="flex space-x-3 pt-2">
                                    <button onClick={() => setShowCreateModal(false)} className="flex-1 px-4 py-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors text-sm font-medium">Cancel</button>
                                    <button onClick={handleCreate} disabled={!formName}
                                        className="flex-1 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-colors text-sm font-medium disabled:opacity-50">
                                        Create Source
                                    </button>
                                </div>
                            </>
                        )}
                    </div>
                </div>
            )}

            {/* Recent Alerts */}
            <div>
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
                        <AlertTriangle className="w-5 h-5 text-amber-400" />
                        <span>Recent SIEM Alerts</span>
                    </h2>
                    <div className="flex items-center space-x-2">
                        {['', 'new', 'investigating', 'resolved', 'ignored'].map(s => (
                            <button key={s} onClick={() => setStatusFilter(s)}
                                className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors ${statusFilter === s ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800/50 text-slate-400 hover:bg-slate-700/50'}`}>
                                {s || 'All'}
                            </button>
                        ))}
                    </div>
                </div>

                {alerts.length === 0 ? (
                    <div className="text-center py-8 text-slate-500 bg-slate-800/30 rounded-xl border border-slate-700/30">
                        <AlertTriangle className="w-10 h-10 mx-auto mb-2 opacity-30" />
                        <p>No alerts received yet</p>
                    </div>
                ) : (
                    <div className="bg-slate-800/30 border border-slate-700/30 rounded-xl overflow-hidden">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-slate-700/50 text-xs text-slate-500 uppercase tracking-wider">
                                    <th className="text-left px-4 py-3">Time</th>
                                    <th className="text-left px-4 py-3">Alert</th>
                                    <th className="text-left px-4 py-3">Severity</th>
                                    <th className="text-left px-4 py-3">Source IP</th>
                                    <th className="text-left px-4 py-3">Status</th>
                                    <th className="text-left px-4 py-3">Investigation</th>
                                    <th className="text-left px-4 py-3">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {alerts.map(alert => (
                                    <tr key={alert.id} className="border-b border-slate-700/20 hover:bg-slate-800/50 transition-colors">
                                        <td className="px-4 py-3 text-xs text-slate-500">{new Date(alert.created_at).toLocaleString()}</td>
                                        <td className="px-4 py-3 text-sm text-slate-300 font-medium max-w-[200px] truncate">{alert.alert_name}</td>
                                        <td className="px-4 py-3">
                                            <span className={`text-xs font-semibold uppercase ${severityColors[alert.severity || 'medium'] || 'text-slate-400'}`}>
                                                {alert.severity || '-'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-xs text-slate-400 font-mono">{alert.source_ip || '-'}</td>
                                        <td className="px-4 py-3">
                                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border ${statusColors[alert.status] || statusColors.new}`}>
                                                {alert.status}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            {alert.task_id ? (
                                                <Link to={`/tasks/${alert.task_id}`} className="text-cyan-400 text-xs hover:underline flex items-center space-x-1">
                                                    <ExternalLink className="w-3 h-3" />
                                                    <span>View</span>
                                                </Link>
                                            ) : '-'}
                                        </td>
                                        <td className="px-4 py-3">
                                            {alert.status === 'new' && user?.role !== 'viewer' && (
                                                <button onClick={() => handleInvestigate(alert.id)}
                                                    className="text-xs px-2 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded hover:bg-cyan-500/20 transition-colors">
                                                    Investigate
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default LogSources;
