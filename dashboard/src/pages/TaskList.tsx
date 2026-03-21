import { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { fetchTasks, fetchStats, type Stats, type TaskListResponse } from '../api/client';
import { Activity, CheckCircle2, XCircle, Search, X, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, AlertTriangle, Clock, ArrowRight, Zap, Target, Cloud } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { Skeleton, CardSkeleton } from '../components/Skeleton';

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
];

const StatusBadge = ({ status }: { status: string }) => {
    const styles: Record<string, string> = {
        completed: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
        failed: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
        executing: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        awaiting_approval: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        rejected: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
        pending: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
    };
    const labels: Record<string, string> = {
        completed: 'Resolved', failed: 'Failed', executing: 'Analyzing',
        awaiting_approval: 'Awaiting Approval', rejected: 'Rejected', pending: 'Pending',
    };
    return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${styles[status] || styles.pending}`}>
            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${status === 'completed' ? 'bg-cyan-500' : status === 'failed' ? 'bg-rose-500' : status === 'executing' ? 'bg-amber-500' : 'bg-slate-500'}`} />
            {labels[status] || 'Pending'}
        </span>
    );
};

const SelectFilter = ({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) => (
    <select value={value} onChange={e => onChange(e.target.value)}
        className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50 min-w-[130px]">
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
);

const TaskList = () => {
    const [searchParams, setSearchParams] = useSearchParams();
    const navigate = useNavigate();
    const [data, setData] = useState<TaskListResponse>({ tasks: [], total: 0, page: 1, limit: 20, pages: 0 });
    const [stats, setStats] = useState<Stats | null>(null);
    const [loading, setLoading] = useState(true);
    const searchRef = useRef<HTMLInputElement>(null);
    const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

    // Read filters from URL
    const search = searchParams.get('search') || '';
    const status = searchParams.get('status') || '';
    const taskType = searchParams.get('task_type') || '';
    const dateFrom = searchParams.get('date_from') || '';
    const dateTo = searchParams.get('date_to') || '';
    const sort = searchParams.get('sort') || 'created_at';
    const order = searchParams.get('order') || 'desc';
    const page = parseInt(searchParams.get('page') || '1');

    const setFilter = useCallback((key: string, value: string) => {
        const params = new URLSearchParams(searchParams);
        if (value) params.set(key, value);
        else params.delete(key);
        if (key !== 'page') params.set('page', '1');
        setSearchParams(params, { replace: true });
    }, [searchParams, setSearchParams]);

    const clearFilters = () => setSearchParams({}, { replace: true });

    const toggleSort = (field: string) => {
        const params = new URLSearchParams(searchParams);
        if (sort === field) {
            params.set('order', order === 'desc' ? 'asc' : 'desc');
        } else {
            params.set('sort', field);
            params.set('order', 'desc');
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
            params.page = String(page);
            params.limit = '20';

            const [taskData, statsData] = await Promise.all([fetchTasks(params), fetchStats()]);
            setData(taskData);
            setStats(statsData);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    }, [search, status, taskType, dateFrom, dateTo, sort, order, page]);

    useEffect(() => {
        loadData();
        document.title = 'Investigations | Hydra';
        // Auto-refresh every 5 seconds for live updates
        const interval = window.setInterval(() => loadData(), 5000);
        return () => clearInterval(interval);
    }, [loadData]);

    const handleSearchInput = (value: string) => {
        if (debounceRef.current) clearTimeout(debounceRef.current);
        debounceRef.current = setTimeout(() => setFilter('search', value), 300);
    };

    const SortHeader = ({ field, label }: { field: string; label: string }) => (
        <th scope="col" onClick={() => toggleSort(field)}
            className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider cursor-pointer hover:text-cyan-400 transition-colors select-none">
            <span className="flex items-center space-x-1">
                <span>{label}</span>
                {sort === field && (order === 'asc' ? <ChevronUp className="w-3 h-3 text-cyan-400" /> : <ChevronDown className="w-3 h-3 text-cyan-400" />)}
            </span>
        </th>
    );


    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-semibold text-slate-100 tracking-tight">Investigations</h1>
                <p className="text-slate-400 text-sm mt-1">Search and filter security analysis across your organization.</p>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {loading || !stats ? (
                    Array.from({ length: 5 }).map((_, i) => <CardSkeleton key={i} />)
                ) : (
                    [
                        { icon: Activity, label: 'Total', value: stats.total_tasks, color: '' },
                        { icon: CheckCircle2, label: 'Resolved', value: stats.completed, color: 'text-cyan-400' },
                        { icon: Clock, label: 'In Progress', value: stats.pending + stats.executing, color: 'text-amber-400' },
                        { icon: XCircle, label: 'Failed', value: stats.failed, color: 'text-rose-400' },
                        { icon: AlertTriangle, label: 'SIEM Alerts', value: stats.siem_alerts_total, color: 'text-violet-400' },
                    ].map(s => (
                        <div key={s.label} className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <s.icon className={`w-4 h-4 mr-2 ${s.color}`} />
                                <span className="text-xs font-medium uppercase tracking-wider">{s.label}</span>
                            </div>
                            <p className={`text-2xl font-bold ${s.color || 'text-white'}`}>{s.value}</p>
                        </div>
                    ))
                )}
            </div>

            {/* Quick Actions */}
            <div>
                <h3 className="text-xs font-bold uppercase tracking-[0.1em] text-cyan-500/80 mb-3 flex items-center">
                    <Zap className="w-3.5 h-3.5 mr-2" /> Quick Actions
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <button
                        onClick={() => navigate('/tasks/new?task_type=ioc_scan&prompt=Scan logs for the following indicators of compromise: ')}
                        className="flex flex-col p-5 bg-[#1E293B] border border-slate-700/50 hover:border-cyan-500/50 rounded-xl transition-all group overflow-hidden relative text-left"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                            <Target className="w-24 h-24" />
                        </div>
                        <div className="rounded-lg bg-cyan-500/10 p-2.5 w-fit mb-4">
                            <Target className="w-5 h-5 text-cyan-400" />
                        </div>
                        <h3 className="text-sm font-bold text-slate-200 mb-1 group-hover:text-cyan-400 transition-colors">Run IOC Scan</h3>
                        <p className="text-xs text-slate-500 leading-relaxed">Instantly hunt for known malicious hashes, IPs, and domains across all connected log sources.</p>
                    </button>

                    <button
                        onClick={() => navigate('/tasks/new?task_type=log_analysis&prompt=Analyze the latest syslog entries for any anomalies or brute force attempts...')}
                        className="flex flex-col p-5 bg-[#1E293B] border border-slate-700/50 hover:border-amber-500/50 rounded-xl transition-all group overflow-hidden relative text-left"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                            <Zap className="w-24 h-24" />
                        </div>
                        <div className="rounded-lg bg-amber-500/10 p-2.5 w-fit mb-4">
                            <Zap className="w-5 h-5 text-amber-400" />
                        </div>
                        <h3 className="text-sm font-bold text-slate-200 mb-1 group-hover:text-amber-400 transition-colors">Analyze Syslog</h3>
                        <p className="text-xs text-slate-500 leading-relaxed">Run a heuristic analysis on recent system logs to detect unauthorized access or lateral movement.</p>
                    </button>

                    <button
                        onClick={() => navigate('/tasks/new?task_type=log_analysis&prompt=Review AWS CloudTrail logs for unexpected IAM role assumptions or privilege escalation...')}
                        className="flex flex-col p-5 bg-[#1E293B] border border-slate-700/50 hover:border-emerald-500/50 rounded-xl transition-all group overflow-hidden relative text-left"
                    >
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                            <Cloud className="w-24 h-24" />
                        </div>
                        <div className="rounded-lg bg-emerald-500/10 p-2.5 w-fit mb-4">
                            <Cloud className="w-5 h-5 text-emerald-400" />
                        </div>
                        <h3 className="text-sm font-bold text-slate-200 mb-1 group-hover:text-emerald-400 transition-colors">Check CloudTrail</h3>
                        <p className="text-xs text-slate-500 leading-relaxed">Audit cloud infrastructure logs for configuration changes, credential theft, or exposed S3 buckets.</p>
                    </button>
                </div>
            </div>

            {/* Search Bar */}
            <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input ref={searchRef} type="text" defaultValue={search} onChange={e => handleSearchInput(e.target.value)}
                    placeholder="Search investigations by prompt, type..."
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50" />
            </div>

            {/* Filter Row */}
            <div className="flex flex-wrap items-center gap-3">
                <SelectFilter value={status} onChange={v => setFilter('status', v)} options={STATUS_OPTIONS} />
                <SelectFilter value={taskType} onChange={v => setFilter('task_type', v)} options={TYPE_OPTIONS} />
                <input type="date" value={dateFrom} onChange={e => setFilter('date_from', e.target.value)}
                    className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50" />
                <span className="text-slate-600 text-xs">to</span>
                <input type="date" value={dateTo} onChange={e => setFilter('date_to', e.target.value)}
                    className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50" />
                {hasFilters && (
                    <button onClick={clearFilters} className="flex items-center space-x-1 px-3 py-2 text-xs text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors">
                        <X className="w-3 h-3" /><span>Clear Filters</span>
                    </button>
                )}
                {loading ? (
                    <Skeleton className="ml-auto w-32 h-4" />
                ) : (
                    <span className="ml-auto text-xs text-slate-500">
                        Showing {data.tasks.length} of {data.total} investigations
                    </span>
                )}
            </div>

            {/* Table */}
            <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-slate-700/50">
                        <thead className="bg-[#0F172A]/50">
                            <tr>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Case ID</th>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Prompt</th>
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Type</th>
                                <SortHeader field="status" label="Status" />
                                <SortHeader field="created_at" label="Opened" />
                                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Duration</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-700/50 bg-[#1E293B]">
                            {loading ? (
                                Array.from({ length: 5 }).map((_, i) => (
                                    <tr key={i} className="animate-pulse">
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-12" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-48" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-6 w-20 rounded-full" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-24" /></td>
                                        <td className="px-6 py-4"><Skeleton className="h-4 w-16" /></td>
                                    </tr>
                                ))
                            ) : data.tasks.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="px-6 py-12 text-center text-sm text-slate-400">
                                        {hasFilters ? 'No investigations match your filters.' : 'No investigations found. Launch a new investigation to get started.'}
                                    </td>
                                </tr>
                            ) : (
                                data.tasks.map((task: any, idx: number) => (
                                    <tr key={task.id} onClick={() => navigate(`/tasks/${task.id}`)}
                                        className={`hover:bg-slate-700/30 cursor-pointer transition-colors ${idx % 2 === 0 ? 'bg-[#1E293B]' : 'bg-[#0F172A]/30'}`}>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-slate-300">{task.id.split('-')[0]}...</td>
                                        <td className="px-6 py-4 text-sm text-slate-400 max-w-[250px] truncate">
                                            {task.prompt ? (task.prompt.length > 60 ? task.prompt.slice(0, 60) + '...' : task.prompt) : '-'}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                                            <span className="px-2.5 py-1 bg-slate-800 rounded-md text-xs font-medium text-slate-300 border border-slate-700/50">
                                                {task.task_type?.replace(/_/g, ' ') || 'Unknown'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap"><StatusBadge status={task.status} /></td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                                            {formatDistanceToNow(new Date(task.created_at), { addSuffix: true })}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400 font-mono">
                                            {task.execution_ms ? `${(task.execution_ms / 1000).toFixed(2)}s` : '-'}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Pagination */}
            {data.pages > 1 && (
                <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-500">Page {data.page} of {data.pages}</span>
                    <div className="flex items-center space-x-2">
                        <button onClick={() => setFilter('page', String(page - 1))} disabled={page <= 1}
                            className="flex items-center space-x-1 px-3 py-1.5 bg-slate-800/50 border border-slate-700/50 rounded-lg text-xs text-slate-400 hover:bg-slate-700/50 transition-colors disabled:opacity-30">
                            <ChevronLeft className="w-3 h-3" /><span>Previous</span>
                        </button>
                        <button onClick={() => setFilter('page', String(page + 1))} disabled={page >= data.pages}
                            className="flex items-center space-x-1 px-3 py-1.5 bg-slate-800/50 border border-slate-700/50 rounded-lg text-xs text-slate-400 hover:bg-slate-700/50 transition-colors disabled:opacity-30">
                            <span>Next</span><ChevronRight className="w-3 h-3" />
                        </button>
                    </div>
                </div>
            )}

            {/* Recent Activity */}
            {stats && stats.recent_activity.length > 0 && !hasFilters && (
                <div>
                    <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">Recent Activity</h2>
                    <div className="bg-slate-800/30 border border-slate-700/30 rounded-xl divide-y divide-slate-700/20">
                        {stats.recent_activity.slice(0, 5).map(act => (
                            <div key={act.id} onClick={() => navigate(`/tasks/${act.id}`)}
                                className="flex items-center justify-between px-4 py-3 hover:bg-slate-800/50 cursor-pointer transition-colors">
                                <div className="flex items-center space-x-3">
                                    <StatusBadge status={act.status} />
                                    <span className="text-sm text-slate-300 truncate max-w-[300px]">
                                        {act.prompt ? (act.prompt.length > 50 ? act.prompt.slice(0, 50) + '...' : act.prompt) : act.task_type}
                                    </span>
                                </div>
                                <div className="flex items-center space-x-2">
                                    <span className="text-xs text-slate-500">{formatDistanceToNow(new Date(act.created_at), { addSuffix: true })}</span>
                                    <ArrowRight className="w-3 h-3 text-slate-600" />
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
