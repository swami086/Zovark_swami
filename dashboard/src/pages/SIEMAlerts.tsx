import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, Search, Filter, X, Loader2, CheckSquare, Square, Play, RefreshCw } from 'lucide-react';
import { fetchSIEMAlerts, investigateAlert, bulkInvestigateAlerts, type SIEMAlert } from '../api/client';
import { Skeleton } from '../components/Skeleton';
import { formatDistanceToNow } from 'date-fns';

const SEVERITY_OPTIONS = [
    { value: '', label: 'All Severities' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'informational', label: 'Informational' },
];

const STATUS_OPTIONS = [
    { value: '', label: 'All Status' },
    { value: 'new', label: 'New' },
    { value: 'investigating', label: 'Investigating' },
    { value: 'resolved', label: 'Resolved' },
    { value: 'dismissed', label: 'Dismissed' },
];

const SeverityBadge = ({ severity }: { severity?: string }) => {
    const s = (severity || 'medium').toLowerCase();
    const colors: Record<string, string> = {
        critical: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
        high: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
        low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
        informational: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
    };
    const dots: Record<string, string> = {
        critical: 'bg-rose-500',
        high: 'bg-amber-500',
        medium: 'bg-yellow-500',
        low: 'bg-blue-500',
        informational: 'bg-slate-500',
    };
    return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border uppercase tracking-wider ${colors[s] || colors.medium}`}>
            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${dots[s] || dots.medium}`} />
            {s}
        </span>
    );
};

const StatusBadge = ({ status }: { status: string }) => {
    const colors: Record<string, string> = {
        new: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
        investigating: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        resolved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
        dismissed: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
    };
    return (
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${colors[status] || colors.new}`}>
            {status}
        </span>
    );
};

export default function SIEMAlerts() {
    const navigate = useNavigate();
    const [alerts, setAlerts] = useState<SIEMAlert[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [severityFilter, setSeverityFilter] = useState('');
    const [statusFilter, setStatusFilter] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
    const [investigating, setInvestigating] = useState<Set<string>>(new Set());
    const [bulkInvestigating, setBulkInvestigating] = useState(false);

    const loadAlerts = useCallback(async () => {
        try {
            setLoading(true);
            const data = await fetchSIEMAlerts(statusFilter || undefined, undefined);
            setAlerts(data.alerts || []);
        } catch (err: any) {
            setError(err.message || 'Failed to load alerts');
        } finally {
            setLoading(false);
        }
    }, [statusFilter]);

    useEffect(() => {
        loadAlerts();
    }, [loadAlerts]);

    const filteredAlerts = alerts.filter(alert => {
        if (severityFilter && alert.severity?.toLowerCase() !== severityFilter) return false;
        if (searchTerm) {
            const search = searchTerm.toLowerCase();
            return (
                alert.alert_name?.toLowerCase().includes(search) ||
                alert.source_ip?.toLowerCase().includes(search) ||
                alert.dest_ip?.toLowerCase().includes(search) ||
                alert.rule_name?.toLowerCase().includes(search)
            );
        }
        return true;
    });

    const toggleSelect = (id: string) => {
        setSelectedIds(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    const toggleSelectAll = () => {
        if (selectedIds.size === filteredAlerts.length) {
            setSelectedIds(new Set());
        } else {
            setSelectedIds(new Set(filteredAlerts.map(a => a.id)));
        }
    };

    const handleInvestigate = async (alertId: string) => {
        setInvestigating(prev => new Set(prev).add(alertId));
        try {
            const result = await investigateAlert(alertId);
            if (result.task_id) {
                navigate(`/tasks/${result.task_id}`);
            } else {
                await loadAlerts();
            }
        } catch (err: any) {
            alert(err.message || 'Failed to investigate alert');
        } finally {
            setInvestigating(prev => {
                const next = new Set(prev);
                next.delete(alertId);
                return next;
            });
        }
    };

    const handleBulkInvestigate = async () => {
        if (selectedIds.size === 0) return;
        setBulkInvestigating(true);
        try {
            await bulkInvestigateAlerts(Array.from(selectedIds));
            setSelectedIds(new Set());
            await loadAlerts();
        } catch (err: any) {
            alert(err.message || 'Failed to bulk investigate');
        } finally {
            setBulkInvestigating(false);
        }
    };

    const hasFilters = severityFilter || statusFilter || searchTerm;

    const clearFilters = () => {
        setSeverityFilter('');
        setStatusFilter('');
        setSearchTerm('');
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white tracking-tight flex items-center">
                        <AlertTriangle className="w-6 h-6 mr-3 text-amber-400" />
                        SIEM Alerts
                    </h1>
                    <p className="text-slate-400 mt-1">Monitor, filter, and investigate security alerts from connected sources</p>
                </div>
                <button
                    onClick={() => { setLoading(true); loadAlerts(); }}
                    className="flex items-center space-x-2 px-3 py-2 bg-slate-800/50 text-slate-400 border border-slate-700/50 rounded-lg hover:bg-slate-700/50 transition-colors"
                >
                    <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    <span className="text-sm">Refresh</span>
                </button>
            </div>

            {error && (
                <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 p-4 rounded-xl">
                    {error}
                </div>
            )}

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {loading ? (
                    Array.from({ length: 5 }).map((_, i) => (
                        <div key={i} className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5 space-y-3">
                            <Skeleton className="w-24 h-3" />
                            <Skeleton className="h-8 w-16" />
                        </div>
                    ))
                ) : (
                    <>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <span className="text-xs font-medium uppercase tracking-wider">Total</span>
                            </div>
                            <p className="text-2xl font-bold text-white">{alerts.length}</p>
                        </div>
                        {['critical', 'high', 'medium', 'low'].map(sev => {
                            const count = alerts.filter(a => a.severity?.toLowerCase() === sev).length;
                            const colorMap: Record<string, string> = {
                                critical: 'text-rose-400',
                                high: 'text-amber-400',
                                medium: 'text-yellow-400',
                                low: 'text-blue-400',
                            };
                            return (
                                <div key={sev} className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                                    <div className="flex items-center text-slate-400 mb-2">
                                        <span className="text-xs font-medium uppercase tracking-wider capitalize">{sev}</span>
                                    </div>
                                    <p className={`text-2xl font-bold ${colorMap[sev]}`}>{count}</p>
                                </div>
                            );
                        })}
                    </>
                )}
            </div>

            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                        type="text" value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
                        placeholder="Search alerts, IPs, rules..."
                        className="w-full pl-10 pr-4 py-2.5 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50"
                    />
                </div>
                <div className="flex items-center space-x-2">
                    <Filter className="w-4 h-4 text-slate-500" />
                    <select
                        value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
                        className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 min-w-[130px]"
                    >
                        {SEVERITY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                    <select
                        value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
                        className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 min-w-[130px]"
                    >
                        {STATUS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                </div>
                {hasFilters && (
                    <button onClick={clearFilters} className="flex items-center space-x-1 px-3 py-2 text-xs text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors">
                        <X className="w-3 h-3" /><span>Clear Filters</span>
                    </button>
                )}
                <span className="ml-auto text-xs text-slate-500">
                    {filteredAlerts.length} of {alerts.length} alerts
                </span>
            </div>

            {/* Bulk Actions */}
            {selectedIds.size > 0 && (
                <div className="flex items-center space-x-4 bg-cyan-500/5 border border-cyan-500/20 rounded-lg px-4 py-3">
                    <span className="text-sm text-cyan-400 font-medium">{selectedIds.size} selected</span>
                    <button
                        onClick={handleBulkInvestigate}
                        disabled={bulkInvestigating}
                        className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 text-white rounded-lg text-xs font-bold hover:bg-cyan-500 transition-colors disabled:opacity-50"
                    >
                        {bulkInvestigating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                        <span>{bulkInvestigating ? 'Investigating...' : 'Investigate Selected'}</span>
                    </button>
                    <button
                        onClick={() => setSelectedIds(new Set())}
                        className="text-xs text-slate-400 hover:text-white transition-colors"
                    >
                        Clear Selection
                    </button>
                </div>
            )}

            {/* Table */}
            <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-slate-700/50">
                        <thead className="bg-[#0F172A]/50">
                            <tr>
                                <th className="px-4 py-4 text-left">
                                    <button onClick={toggleSelectAll} className="text-slate-500 hover:text-white transition-colors">
                                        {selectedIds.size === filteredAlerts.length && filteredAlerts.length > 0
                                            ? <CheckSquare className="w-4 h-4 text-cyan-400" />
                                            : <Square className="w-4 h-4" />}
                                    </button>
                                </th>
                                <th className="px-4 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Alert</th>
                                <th className="px-4 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Severity</th>
                                <th className="px-4 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Source IP</th>
                                <th className="px-4 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Dest IP</th>
                                <th className="px-4 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Status</th>
                                <th className="px-4 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Time</th>
                                <th className="px-4 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-700/50 bg-[#1E293B]">
                            {loading ? (
                                Array.from({ length: 5 }).map((_, i) => (
                                    <tr key={i} className="animate-pulse">
                                        <td className="px-4 py-4"><Skeleton className="h-4 w-4" /></td>
                                        <td className="px-4 py-4"><Skeleton className="h-4 w-48" /></td>
                                        <td className="px-4 py-4"><Skeleton className="h-6 w-20 rounded-full" /></td>
                                        <td className="px-4 py-4"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-4 py-4"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-4 py-4"><Skeleton className="h-4 w-16" /></td>
                                        <td className="px-4 py-4"><Skeleton className="h-4 w-20" /></td>
                                        <td className="px-4 py-4"><Skeleton className="h-4 w-20" /></td>
                                    </tr>
                                ))
                            ) : filteredAlerts.length === 0 ? (
                                <tr>
                                    <td colSpan={8} className="px-6 py-12 text-center text-sm text-slate-400">
                                        {hasFilters ? 'No alerts match your filters.' : 'No SIEM alerts found.'}
                                    </td>
                                </tr>
                            ) : (
                                filteredAlerts.map((alert, idx) => (
                                    <tr key={alert.id} className={`hover:bg-slate-700/30 transition-colors ${idx % 2 === 0 ? 'bg-[#1E293B]' : 'bg-[#0F172A]/30'}`}>
                                        <td className="px-4 py-4">
                                            <button onClick={() => toggleSelect(alert.id)} className="text-slate-500 hover:text-white transition-colors">
                                                {selectedIds.has(alert.id)
                                                    ? <CheckSquare className="w-4 h-4 text-cyan-400" />
                                                    : <Square className="w-4 h-4" />}
                                            </button>
                                        </td>
                                        <td className="px-4 py-4">
                                            <div>
                                                <p className="text-sm font-medium text-slate-200 truncate max-w-[250px]">{alert.alert_name}</p>
                                                {alert.rule_name && <p className="text-xs text-slate-500 font-mono mt-0.5">{alert.rule_name}</p>}
                                            </div>
                                        </td>
                                        <td className="px-4 py-4"><SeverityBadge severity={alert.severity} /></td>
                                        <td className="px-4 py-4 text-xs font-mono text-slate-400">{alert.source_ip || '-'}</td>
                                        <td className="px-4 py-4 text-xs font-mono text-slate-400">{alert.dest_ip || '-'}</td>
                                        <td className="px-4 py-4"><StatusBadge status={alert.status} /></td>
                                        <td className="px-4 py-4 text-xs text-slate-500">
                                            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                                        </td>
                                        <td className="px-4 py-4">
                                            <div className="flex items-center space-x-2">
                                                {alert.task_id ? (
                                                    <button
                                                        onClick={() => navigate(`/tasks/${alert.task_id}`)}
                                                        className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-medium text-cyan-400 hover:bg-cyan-500/10 rounded-lg transition-colors"
                                                    >
                                                        <span>View</span>
                                                    </button>
                                                ) : (
                                                    <button
                                                        onClick={() => handleInvestigate(alert.id)}
                                                        disabled={investigating.has(alert.id)}
                                                        className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 rounded-lg transition-colors disabled:opacity-50"
                                                    >
                                                        {investigating.has(alert.id) ? (
                                                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                                        ) : (
                                                            <Play className="w-3.5 h-3.5" />
                                                        )}
                                                        <span>Investigate</span>
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
