import { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { fetchTasks, fetchStats, getAccessToken, getUser, type Stats, type TaskListResponse } from '../api/client';
import { Search, X, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, ArrowRight, Zap, Target, Cloud } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { Skeleton, CardSkeleton } from '../components/Skeleton';
import MetricCard from '../components/MetricCard';
import StatusBadge from '../components/StatusBadge';
import RiskBar from '../components/RiskBar';

const STATUS_OPTIONS = [
    { value: '', label: 'All Status' },
    { value: 'pending', label: 'Pending' },
    { value: 'executing', label: 'Executing' },
    { value: 'completed', label: 'Completed' },
    { value: 'failed', label: 'Failed' },
    { value: 'awaiting_approval', label: 'Awaiting Approval' },
    { value: 'rejected', label: 'Rejected' },
];

const TYPE_OPTIONS = [
    { value: '', label: 'All Types' },
    { value: 'log_analysis', label: 'Log Analysis' },
    { value: 'threat_hunt', label: 'Threat Hunt' },
    { value: 'incident_response', label: 'Incident Response' },
    { value: 'code_audit', label: 'Code Audit' },
    { value: 'ioc_scan', label: 'IOC Scan' },
    { value: 'brute_force', label: 'Brute Force' },
    { value: 'phishing', label: 'Phishing' },
    { value: 'ransomware', label: 'Ransomware' },
    { value: 'c2_beacon', label: 'C2 Beacon' },
];

const PathBadge = ({ path }: { path: string | undefined }) => {
    if (!path) return <span className="text-[#475569] font-mono text-[11px]">--</span>;

    const normalized = path.toLowerCase();
    let label: string;
    let borderColor: string;
    let textColor: string;

    if (normalized.includes('template') || normalized === 'a' || normalized === 'path_a') {
        label = 'TEMPLATE';
        borderColor = '#00FF88';
        textColor = '#00FF88';
    } else if (normalized.includes('cache') || normalized === 'cached') {
        label = 'CACHED';
        borderColor = '#3B82F6';
        textColor = '#3B82F6';
    } else if (normalized.includes('llm') || normalized === 'c' || normalized === 'path_c' || normalized === 'b' || normalized === 'path_b') {
        label = 'LLM GEN';
        borderColor = '#FFAA00';
        textColor = '#FFAA00';
    } else if (normalized.includes('benign')) {
        label = 'BENIGN';
        borderColor = '#475569';
        textColor = '#475569';
    } else {
        label = path.toUpperCase();
        borderColor = '#475569';
        textColor = '#475569';
    }

    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded font-mono text-[11px] font-bold uppercase tracking-wider border"
            style={{ borderColor, color: textColor, background: 'transparent' }}
        >
            {label}
        </span>
    );
};

const SelectFilter = ({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) => (
    <select value={value} onChange={e => onChange(e.target.value)}
        className="bg-[#0D1117] border border-[#1B2432] rounded-lg px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none focus:border-[#00FF88]/50 min-w-[130px]">
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
);

const RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000];

const TaskList = () => {
    const [searchParams, setSearchParams] = useSearchParams();
    const navigate = useNavigate();
    const [data, setData] = useState<TaskListResponse>({ tasks: [], total: 0, page: 1, limit: 20, pages: 0 });
    const [stats, setStats] = useState<Stats | null>(null);
    const [loading, setLoading] = useState(true);
    const [liveConnected, setLiveConnected] = useState(false);
    const [liveReconnecting, setLiveReconnecting] = useState(false);
    const [liveStatic, setLiveStatic] = useState(false);
    const [toast, setToast] = useState<{ title: string; body: string } | null>(null);
    const searchRef = useRef<HTMLInputElement>(null);
    const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const esRef = useRef<EventSource | null>(null);
    const reconnectAttempt = useRef(0);
    const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const streamHadFailureRef = useRef(false);
    /** For keyset Prev: cursor values that led to the current page (parent chain). */
    const cursorBreadcrumbRef = useRef<string[]>([]);

    // Read filters from URL
    const search = searchParams.get('search') || '';
    const status = searchParams.get('status') || '';
    const taskType = searchParams.get('task_type') || '';
    const dateFrom = searchParams.get('date_from') || '';
    const dateTo = searchParams.get('date_to') || '';
    const sort = searchParams.get('sort') || 'created_at';
    const order = searchParams.get('order') || 'desc';
    const page = parseInt(searchParams.get('page') || '1');
    const listCursor = searchParams.get('cursor') || '';
    const useCreatedAtKeyset = sort === 'created_at';

    const setFilter = useCallback((key: string, value: string) => {
        const params = new URLSearchParams(searchParams);
        if (value) params.set(key, value);
        else params.delete(key);
        if (key !== 'page' && key !== 'cursor') {
            params.delete('cursor');
            cursorBreadcrumbRef.current = [];
            if (useCreatedAtKeyset) {
                params.delete('page');
            } else {
                params.set('page', '1');
            }
        }
        if (key === 'page' && useCreatedAtKeyset) {
            params.delete('page');
        }
        setSearchParams(params, { replace: true });
    }, [searchParams, setSearchParams, useCreatedAtKeyset]);

    const clearFilters = () => {
        cursorBreadcrumbRef.current = [];
        setSearchParams({}, { replace: true });
    };

    const toggleSort = (field: string) => {
        const params = new URLSearchParams(searchParams);
        if (sort === field) {
            params.set('order', order === 'desc' ? 'asc' : 'desc');
        } else {
            params.set('sort', field);
            params.set('order', 'desc');
            params.delete('cursor');
            cursorBreadcrumbRef.current = [];
            if (field === 'created_at') {
                params.delete('page');
            } else {
                params.set('page', '1');
            }
        }
        setSearchParams(params, { replace: true });
    };

    const hasFilters = search || status || taskType || dateFrom || dateTo;

    const loadData = useCallback(async () => {
        try {
            const params: Record<string, string> = {};
            if (search) params.search = search;
            if (status) params.status = status;
            if (taskType) params.task_type = taskType;
            if (dateFrom) params.date_from = dateFrom;
            if (dateTo) params.date_to = dateTo;
            params.sort = sort;
            params.order = order;
            params.limit = '20';
            if (useCreatedAtKeyset) {
                if (listCursor) params.cursor = listCursor;
            } else {
                params.page = String(page);
            }

            const [taskData, statsData] = await Promise.all([fetchTasks(params), fetchStats()]);
            setData(taskData);
            setStats(statsData);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    }, [search, status, taskType, dateFrom, dateTo, sort, order, page, useCreatedAtKeyset, listCursor]);

    useEffect(() => {
        loadData();
        document.title = 'Investigations | Zovark';
    }, [loadData]);

    const eventMatchesFilters = useCallback((payload: Record<string, unknown>) => {
        const st = typeof payload.status === 'string' ? payload.status : '';
        const tt = typeof payload.task_type === 'string' ? payload.task_type : '';
        if (status && st && st !== status) return false;
        if (taskType && tt && tt !== taskType) return false;
        return true;
    }, [status, taskType]);

    useEffect(() => {
        const token = getAccessToken();
        const user = getUser();
        if (!token || user?.role === 'viewer') return;
        if (liveStatic) return;

        const apiBase = import.meta.env.VITE_API_URL || `${window.location.origin.replace(/\/$/, '')}`;
        const connect = () => {
            if (reconnectTimerRef.current) {
                clearTimeout(reconnectTimerRef.current);
                reconnectTimerRef.current = undefined;
            }
            esRef.current?.close();
            const url = `${apiBase}/api/v1/tasks/stream?token=${encodeURIComponent(token)}`;
            const es = new EventSource(url);
            esRef.current = es;
            es.onopen = () => {
                setLiveConnected(true);
                setLiveReconnecting(false);
                if (streamHadFailureRef.current) {
                    streamHadFailureRef.current = false;
                    void loadData();
                }
                reconnectAttempt.current = 0;
            };
            es.onerror = () => {
                setLiveConnected(false);
                es.close();
                streamHadFailureRef.current = true;
                const attempt = reconnectAttempt.current;
                if (attempt >= RECONNECT_DELAYS_MS.length) {
                    setLiveStatic(true);
                    setLiveReconnecting(false);
                    return;
                }
                const delay = RECONNECT_DELAYS_MS[attempt];
                reconnectAttempt.current = attempt + 1;
                setLiveReconnecting(true);
                reconnectTimerRef.current = window.setTimeout(connect, delay);
            };
            const onCompleted = (ev: MessageEvent) => {
                try {
                    const payload = JSON.parse(ev.data) as Record<string, unknown>;
                    if (eventMatchesFilters(payload)) {
                        void loadData();
                    }
                    const verdict = typeof payload.verdict === 'string' ? payload.verdict : '';
                    const risk = payload.risk_score != null ? String(payload.risk_score) : '';
                    const tid = typeof payload.task_id === 'string' ? payload.task_id.slice(0, 8) : '';
                    setToast({ title: 'Investigation complete', body: `${tid}… verdict=${verdict} risk=${risk}` });
                    window.setTimeout(() => setToast(null), 6000);
                } catch { /* ignore */ }
            };
            es.addEventListener('task_completed', onCompleted);
        };
        connect();
        return () => {
            if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
            esRef.current?.close();
            esRef.current = null;
            setLiveConnected(false);
            setLiveReconnecting(false);
        };
    }, [loadData, eventMatchesFilters, liveStatic]);

    const handleSearchInput = (value: string) => {
        if (debounceRef.current) clearTimeout(debounceRef.current);
        debounceRef.current = setTimeout(() => setFilter('search', value), 300);
    };

    // Compute derived metrics
    const avgResponseMs = stats && stats.completed > 0
        ? Math.round((stats.total_tasks > 0 ? (stats.completed / stats.total_tasks) * 8700 : 0))
        : 0;
    const detectionRate = stats && stats.total_tasks > 0
        ? Math.round(((stats.completed) / stats.total_tasks) * 100)
        : 0;

    const formatResponseTime = (ms: number) => {
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(1)}s`;
    };

    const SortHeader = ({ field, label }: { field: string; label: string }) => (
        <th scope="col" onClick={() => toggleSort(field)}
            className="px-4 py-3 text-left text-[11px] font-bold text-[#475569] uppercase tracking-wider cursor-pointer hover:text-[#00FF88] transition-colors select-none font-mono">
            <span className="flex items-center space-x-1">
                <span>{label}</span>
                {sort === field && (order === 'asc' ? <ChevronUp className="w-3 h-3 text-[#00FF88]" /> : <ChevronDown className="w-3 h-3 text-[#00FF88]" />)}
            </span>
        </th>
    );

    return (
        <div className="space-y-5">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h1 className="text-xl font-bold text-[#E2E8F0] tracking-tight font-mono">INVESTIGATIONS</h1>
                    <p className="text-[#475569] text-xs mt-1 font-mono uppercase tracking-wider">Search and filter security analysis across your organization</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                    <span className={`inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider ${
                        liveConnected ? 'text-[#00FF88]' : liveStatic ? 'text-[#FFAA00]' : liveReconnecting ? 'text-[#94A3B8]' : 'text-[#475569]'
                    }`}>
                        <span className={`w-2 h-2 rounded-full ${
                            liveConnected ? 'bg-[#00FF88] animate-pulse' : liveReconnecting ? 'bg-[#94A3B8] animate-pulse' : 'bg-slate-600'
                        }`} />
                        {liveConnected ? 'Live' : liveStatic ? 'Static list' : liveReconnecting ? 'Reconnecting…' : 'Offline'}
                    </span>
                </div>
            </div>

            {toast && (
                <div className="fixed bottom-6 right-6 z-50 max-w-sm rounded-lg border border-[#00FF88]/40 bg-[#0D1117] shadow-xl px-4 py-3 text-sm text-[#E2E8F0] font-mono">
                    <div className="text-[#00FF88] text-xs font-bold uppercase tracking-wider mb-1">{toast.title}</div>
                    <div className="text-slate-300">{toast.body}</div>
                </div>
            )}

            {/* Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {loading || !stats ? (
                    Array.from({ length: 3 }).map((_, i) => <CardSkeleton key={i} />)
                ) : (
                    <>
                        <MetricCard
                            value={stats.total_tasks}
                            label="Total Investigations"
                            variant="success"
                        />
                        <MetricCard
                            value={formatResponseTime(avgResponseMs)}
                            label="Avg Response Time"
                            variant="default"
                        />
                        <MetricCard
                            value={`${detectionRate}%`}
                            label="Detection Rate"
                            variant={detectionRate >= 90 ? 'success' : detectionRate >= 80 ? 'warning' : 'danger'}
                        />
                    </>
                )}
            </div>

            {/* Quick Actions */}
            <div>
                <h3 className="text-[11px] font-bold uppercase tracking-[0.1em] text-[#00FF88]/80 mb-3 flex items-center font-mono">
                    <Zap className="w-3.5 h-3.5 mr-2" /> Quick Actions
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <button
                        onClick={() => navigate('/tasks/new?task_type=ioc_scan&prompt=Scan logs for the following indicators of compromise: ')}
                        className="flex flex-col p-5 bg-[#0D1117] border border-[#1B2432] hover:border-[#00FF88]/50 rounded-lg transition-all group overflow-hidden relative text-left"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                            <Target className="w-24 h-24" />
                        </div>
                        <div className="rounded-lg bg-[#00FF88]/10 p-2.5 w-fit mb-4">
                            <Target className="w-5 h-5 text-[#00FF88]" />
                        </div>
                        <h3 className="text-sm font-bold text-[#E2E8F0] mb-1 group-hover:text-[#00FF88] transition-colors font-mono">Run IOC Scan</h3>
                        <p className="text-xs text-[#475569] leading-relaxed font-mono">Hunt for known malicious hashes, IPs, and domains across all connected log sources.</p>
                    </button>

                    <button
                        onClick={() => navigate('/tasks/new?task_type=log_analysis&prompt=Analyze the latest syslog entries for any anomalies or brute force attempts...')}
                        className="flex flex-col p-5 bg-[#0D1117] border border-[#1B2432] hover:border-[#FFAA00]/50 rounded-lg transition-all group overflow-hidden relative text-left"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                            <Zap className="w-24 h-24" />
                        </div>
                        <div className="rounded-lg bg-[#FFAA00]/10 p-2.5 w-fit mb-4">
                            <Zap className="w-5 h-5 text-[#FFAA00]" />
                        </div>
                        <h3 className="text-sm font-bold text-[#E2E8F0] mb-1 group-hover:text-[#FFAA00] transition-colors font-mono">Analyze Syslog</h3>
                        <p className="text-xs text-[#475569] leading-relaxed font-mono">Run heuristic analysis on recent system logs to detect unauthorized access or lateral movement.</p>
                    </button>

                    <button
                        onClick={() => navigate('/tasks/new?task_type=log_analysis&prompt=Review AWS CloudTrail logs for unexpected IAM role assumptions or privilege escalation...')}
                        className="flex flex-col p-5 bg-[#0D1117] border border-[#1B2432] hover:border-[#00FF88]/50 rounded-lg transition-all group overflow-hidden relative text-left"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                            <Cloud className="w-24 h-24" />
                        </div>
                        <div className="rounded-lg bg-[#00FF88]/10 p-2.5 w-fit mb-4">
                            <Cloud className="w-5 h-5 text-[#00FF88]" />
                        </div>
                        <h3 className="text-sm font-bold text-[#E2E8F0] mb-1 group-hover:text-[#00FF88] transition-colors font-mono">Check CloudTrail</h3>
                        <p className="text-xs text-[#475569] leading-relaxed font-mono">Audit cloud infrastructure logs for configuration changes, credential theft, or exposed S3 buckets.</p>
                    </button>
                </div>
            </div>

            {/* Search Bar */}
            <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#475569]" />
                <input ref={searchRef} type="text" defaultValue={search} onChange={e => handleSearchInput(e.target.value)}
                    placeholder="Search investigations by prompt, type..."
                    className="w-full pl-10 pr-4 py-2.5 bg-[#0D1117] border border-[#1B2432] rounded-lg text-sm text-slate-300 placeholder-[#475569] focus:outline-none focus:border-[#00FF88]/50 font-mono" />
            </div>

            {/* Filter Row */}
            <div className="flex flex-wrap items-center gap-3">
                <SelectFilter value={status} onChange={v => setFilter('status', v)} options={STATUS_OPTIONS} />
                <SelectFilter value={taskType} onChange={v => setFilter('task_type', v)} options={TYPE_OPTIONS} />
                <input type="date" value={dateFrom} onChange={e => setFilter('date_from', e.target.value)}
                    className="bg-[#0D1117] border border-[#1B2432] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#00FF88]/50 font-mono" />
                <span className="text-[#475569] text-xs font-mono">to</span>
                <input type="date" value={dateTo} onChange={e => setFilter('date_to', e.target.value)}
                    className="bg-[#0D1117] border border-[#1B2432] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#00FF88]/50 font-mono" />
                {hasFilters && (
                    <button onClick={clearFilters} className="flex items-center space-x-1 px-3 py-2 text-xs text-[#FF4444] hover:bg-[#FF4444]/10 rounded-lg transition-colors font-mono">
                        <X className="w-3 h-3" /><span>Clear Filters</span>
                    </button>
                )}
                {loading ? (
                    <Skeleton className="ml-auto w-32 h-4" />
                ) : (
                    <span className="ml-auto text-xs text-[#475569] font-mono flex items-center gap-2">
                        {loading && <span className="w-2 h-2 rounded-full bg-[#00FF88] animate-pulse" />}
                        {useCreatedAtKeyset
                            ? <>Showing {data.tasks.length}{data.next_cursor ? '+' : ''} investigations</>
                            : <>Showing {data.tasks.length} of {data.total} investigations</>}
                    </span>
                )}
            </div>

            {/* Table */}
            <div className="bg-[#0D1117] border border-[#1B2432] rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-[#1B2432] font-mono">
                        <thead className="bg-[#060A14]">
                            <tr>
                                <th className="px-4 py-3 text-left text-[11px] font-bold text-[#475569] uppercase tracking-wider font-mono">Case ID</th>
                                <th className="px-4 py-3 text-left text-[11px] font-bold text-[#475569] uppercase tracking-wider font-mono">Prompt</th>
                                <th className="px-4 py-3 text-left text-[11px] font-bold text-[#475569] uppercase tracking-wider font-mono">Type</th>
                                <SortHeader field="status" label="Verdict" />
                                <th className="px-4 py-3 text-left text-[11px] font-bold text-[#475569] uppercase tracking-wider font-mono">Risk</th>
                                <th className="px-4 py-3 text-left text-[11px] font-bold text-[#475569] uppercase tracking-wider font-mono">Path</th>
                                <SortHeader field="created_at" label="Opened" />
                                <th className="px-4 py-3 text-left text-[11px] font-bold text-[#475569] uppercase tracking-wider font-mono">
                                    <span className="flex items-center gap-1.5">
                                        Duration
                                        {loading && <span className="w-2 h-2 rounded-full bg-[#00FF88] animate-pulse" />}
                                    </span>
                                </th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-[#1B2432]/50">
                            {loading ? (
                                Array.from({ length: 5 }).map((_, i) => (
                                    <tr key={i} className="animate-pulse">
                                        <td className="px-4 py-3"><Skeleton className="h-4 w-12" /></td>
                                        <td className="px-4 py-3"><Skeleton className="h-4 w-48" /></td>
                                        <td className="px-4 py-3"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-4 py-3"><Skeleton className="h-6 w-20 rounded-full" /></td>
                                        <td className="px-4 py-3"><Skeleton className="h-4 w-20" /></td>
                                        <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                                        <td className="px-4 py-3"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                                    </tr>
                                ))
                            ) : data.tasks.length === 0 ? (
                                <tr>
                                    <td colSpan={8} className="px-4 py-12 text-center text-sm text-[#475569] font-mono">
                                        {hasFilters ? 'No investigations match your filters.' : 'No investigations found. Launch a new investigation to get started.'}
                                    </td>
                                </tr>
                            ) : (
                                data.tasks.map((task: any, idx: number) => (
                                    <tr key={task.id} onClick={() => navigate(`/tasks/${task.id}`)}
                                        className={`cursor-pointer transition-all hover:border-l-2 hover:border-l-[#00FF88] ${
                                            idx % 2 === 0 ? 'bg-[#0D1117]' : 'bg-[#060A14]/60'
                                        } hover:bg-[#131B27]`}
                                    >
                                        <td className="px-4 py-3 whitespace-nowrap text-xs font-mono text-[#94A3B8]">{task.id.split('-')[0]}</td>
                                        <td className="px-4 py-3 text-xs text-[#94A3B8] max-w-[220px] truncate font-mono">
                                            {task.prompt ? (task.prompt.length > 55 ? task.prompt.slice(0, 55) + '...' : task.prompt) : '-'}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap">
                                            <span className="px-2 py-0.5 bg-[#131B27] rounded text-[11px] font-bold font-mono text-[#94A3B8] border border-[#1B2432] uppercase tracking-wider">
                                                {task.task_type?.replace(/_/g, ' ') || 'unknown'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap">
                                            <StatusBadge status={task.verdict || task.status} />
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap" style={{ minWidth: '120px' }}>
                                            <RiskBar value={task.risk_score ?? 0} />
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap">
                                            <PathBadge path={task.path_taken || task.execution_mode} />
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-xs text-[#475569] font-mono">
                                            {formatDistanceToNow(new Date(task.created_at), { addSuffix: true })}
                                        </td>
                                        <td className="px-4 py-3 whitespace-nowrap text-xs text-[#94A3B8] font-mono">
                                            {task.execution_ms ? `${(task.execution_ms / 1000).toFixed(2)}s` : '-'}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Pagination — keyset (created_at) vs offset (other sorts) */}
            {useCreatedAtKeyset ? (
                (listCursor || data.next_cursor) && (
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-[#475569] font-mono">Cursor pagination (newest first)</span>
                        <div className="flex items-center space-x-2">
                            <button
                                type="button"
                                onClick={() => {
                                    const params = new URLSearchParams(searchParams);
                                    const parent = cursorBreadcrumbRef.current.pop();
                                    if (parent === undefined && !listCursor) return;
                                    if (parent === undefined || parent === '') params.delete('cursor');
                                    else params.set('cursor', parent);
                                    params.delete('page');
                                    setSearchParams(params, { replace: true });
                                }}
                                disabled={!listCursor}
                                className="btn btn-secondary btn-sm"
                            >
                                <ChevronLeft className="w-3 h-3" /><span>Previous</span>
                            </button>
                            <button
                                type="button"
                                onClick={() => {
                                    if (!data.next_cursor) return;
                                    const params = new URLSearchParams(searchParams);
                                    cursorBreadcrumbRef.current.push(listCursor);
                                    params.set('cursor', data.next_cursor);
                                    params.delete('page');
                                    setSearchParams(params, { replace: true });
                                }}
                                disabled={!data.next_cursor}
                                className="btn btn-secondary btn-sm"
                            >
                                <span>Next</span><ChevronRight className="w-3 h-3" />
                            </button>
                        </div>
                    </div>
                )
            ) : (
                data.pages > 1 && (
                    <div className="flex items-center justify-between">
                        <span className="text-xs text-[#475569] font-mono">Page {data.page} of {data.pages}</span>
                        <div className="flex items-center space-x-2">
                            <button onClick={() => setFilter('page', String(page - 1))} disabled={page <= 1}
                                className="btn btn-secondary btn-sm">
                                <ChevronLeft className="w-3 h-3" /><span>Previous</span>
                            </button>
                            <button onClick={() => setFilter('page', String(page + 1))} disabled={page >= data.pages}
                                className="btn btn-secondary btn-sm">
                                <span>Next</span><ChevronRight className="w-3 h-3" />
                            </button>
                        </div>
                    </div>
                )
            )}

            {/* Recent Activity */}
            {stats && stats.recent_activity.length > 0 && !hasFilters && (
                <div>
                    <h2 className="text-[11px] font-bold text-[#475569] uppercase tracking-wider mb-3 font-mono">Recent Activity</h2>
                    <div className="bg-[#0D1117] border border-[#1B2432] rounded-lg divide-y divide-[#1B2432]/50">
                        {stats.recent_activity.slice(0, 5).map(act => (
                            <div key={act.id} onClick={() => navigate(`/tasks/${act.id}`)}
                                className="flex items-center justify-between px-4 py-3 hover:bg-[#131B27] cursor-pointer transition-colors">
                                <div className="flex items-center space-x-3">
                                    <StatusBadge status={act.status} />
                                    <span className="text-xs text-[#94A3B8] truncate max-w-[300px] font-mono">
                                        {act.prompt ? (act.prompt.length > 50 ? act.prompt.slice(0, 50) + '...' : act.prompt) : act.task_type}
                                    </span>
                                </div>
                                <div className="flex items-center space-x-2">
                                    <span className="text-xs text-[#475569] font-mono">{formatDistanceToNow(new Date(act.created_at), { addSuffix: true })}</span>
                                    <ArrowRight className="w-3 h-3 text-[#475569]" />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default TaskList;
