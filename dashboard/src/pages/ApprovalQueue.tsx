import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, CheckCircle, XCircle, RefreshCw, Code2, AlertTriangle, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import { fetchPendingApprovals, decideApproval, type ApprovalRequest } from '../api/client';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Skeleton } from '../components/Skeleton';
import { formatDistanceToNow } from 'date-fns';

const RiskBadge = ({ level }: { level: string }) => {
    const colors: Record<string, string> = {
        critical: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
        high: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
        low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    };
    return (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border uppercase tracking-wider ${colors[level] || colors.medium}`}>
            {level}
        </span>
    );
};

export default function ApprovalQueue() {
    const navigate = useNavigate();
    const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
    const [decidingIds, setDecidingIds] = useState<Set<string>>(new Set());
    const [comments, setComments] = useState<Record<string, string>>({});
    const [confirmAction, setConfirmAction] = useState<{ id: string; approved: boolean } | null>(null);

    const loadApprovals = useCallback(async () => {
        try {
            const data = await fetchPendingApprovals();
            setApprovals(data.approvals || []);
        } catch (err: any) {
            setError(err.message || 'Failed to load approvals');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadApprovals();
        const interval = setInterval(loadApprovals, 15000);
        return () => clearInterval(interval);
    }, [loadApprovals]);

    const toggleExpanded = (id: string) => {
        setExpandedIds(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    const handleDecide = async (id: string, approved: boolean) => {
        setDecidingIds(prev => new Set(prev).add(id));
        try {
            await decideApproval(id, approved, comments[id] || '');
            setApprovals(prev => prev.filter(a => a.id !== id));
            setConfirmAction(null);
        } catch (err: any) {
            alert(err.message || 'Failed to submit decision');
        } finally {
            setDecidingIds(prev => {
                const next = new Set(prev);
                next.delete(id);
                return next;
            });
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white tracking-tight flex items-center">
                        <ShieldAlert className="w-6 h-6 mr-3 text-amber-400" />
                        Approval Queue
                    </h1>
                    <p className="text-slate-400 mt-1">Review and approve pending investigation actions</p>
                </div>
                <div className="flex items-center space-x-3">
                    <span className="text-xs text-slate-500">Auto-refreshes every 15s</span>
                    <button
                        onClick={() => { setLoading(true); loadApprovals(); }}
                        className="flex items-center space-x-2 px-3 py-2 bg-slate-800/50 text-slate-400 border border-slate-700/50 rounded-lg hover:bg-slate-700/50 transition-colors"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                        <span className="text-sm">Refresh</span>
                    </button>
                </div>
            </div>

            {error && (
                <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 p-4 rounded-xl">
                    {error}
                </div>
            )}

            {/* Summary */}
            <div className="grid grid-cols-3 gap-4">
                <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                    <div className="flex items-center text-slate-400 mb-2">
                        <Clock className="w-4 h-4 mr-2 text-amber-400" />
                        <span className="text-xs font-medium uppercase tracking-wider">Pending</span>
                    </div>
                    <p className="text-2xl font-bold text-amber-400">{loading ? '-' : approvals.length}</p>
                </div>
                <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                    <div className="flex items-center text-slate-400 mb-2">
                        <AlertTriangle className="w-4 h-4 mr-2 text-rose-400" />
                        <span className="text-xs font-medium uppercase tracking-wider">Critical Risk</span>
                    </div>
                    <p className="text-2xl font-bold text-rose-400">
                        {loading ? '-' : approvals.filter(a => a.risk_level === 'critical').length}
                    </p>
                </div>
                <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                    <div className="flex items-center text-slate-400 mb-2">
                        <Code2 className="w-4 h-4 mr-2 text-cyan-400" />
                        <span className="text-xs font-medium uppercase tracking-wider">Avg Step</span>
                    </div>
                    <p className="text-2xl font-bold text-cyan-400">
                        {loading || approvals.length === 0 ? '-' : Math.round(approvals.reduce((s, a) => s + a.step_number, 0) / approvals.length)}
                    </p>
                </div>
            </div>

            {/* Approval Cards */}
            {loading ? (
                <div className="space-y-4">
                    {Array.from({ length: 3 }).map((_, i) => (
                        <div key={i} className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6 space-y-4 animate-pulse">
                            <Skeleton className="h-5 w-64" />
                            <Skeleton className="h-4 w-48" />
                            <Skeleton className="h-20 w-full" />
                        </div>
                    ))}
                </div>
            ) : approvals.length === 0 ? (
                <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-12 text-center">
                    <CheckCircle className="w-12 h-12 text-emerald-400 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-white mb-2">All Clear</h3>
                    <p className="text-sm text-slate-400">No pending approvals. All investigations are proceeding normally.</p>
                </div>
            ) : (
                <div className="space-y-4">
                    {approvals.map(approval => {
                        const isExpanded = expandedIds.has(approval.id);
                        const isDeciding = decidingIds.has(approval.id);
                        return (
                            <div key={approval.id} className="bg-[#1E293B] border border-slate-700/50 rounded-xl overflow-hidden">
                                {/* Header */}
                                <div className="p-5">
                                    <div className="flex items-start justify-between mb-3">
                                        <div className="flex-1">
                                            <div className="flex items-center space-x-3 mb-2">
                                                <RiskBadge level={approval.risk_level} />
                                                <span className="text-xs text-slate-500 font-mono">Step {approval.step_number}</span>
                                                <span className="text-xs text-slate-500">
                                                    {formatDistanceToNow(new Date(approval.requested_at), { addSuffix: true })}
                                                </span>
                                            </div>
                                            <h3 className="text-sm font-semibold text-slate-200 mb-1">
                                                {approval.action_summary || 'Code execution requires approval'}
                                            </h3>
                                            <p className="text-xs text-slate-500 truncate max-w-lg">
                                                {approval.prompt || '-'}
                                            </p>
                                        </div>
                                        <button
                                            onClick={() => navigate(`/tasks/${approval.task_id}`)}
                                            className="ml-4 px-3 py-1.5 text-xs font-medium text-cyan-400 hover:bg-cyan-500/10 rounded-lg transition-colors whitespace-nowrap"
                                        >
                                            View Investigation
                                        </button>
                                    </div>

                                    {/* Toggle code */}
                                    <button
                                        onClick={() => toggleExpanded(approval.id)}
                                        className="flex items-center space-x-1 text-xs text-slate-400 hover:text-cyan-400 transition-colors"
                                    >
                                        <Code2 className="w-3.5 h-3.5" />
                                        <span>{isExpanded ? 'Hide' : 'Show'} Generated Code</span>
                                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                                    </button>

                                    {isExpanded && approval.generated_code && (
                                        <div className="mt-3 rounded-lg overflow-hidden border border-slate-700/50">
                                            <SyntaxHighlighter
                                                language="python"
                                                style={atomDark}
                                                customStyle={{ margin: 0, fontSize: '12px', maxHeight: '300px' }}
                                            >
                                                {approval.generated_code}
                                            </SyntaxHighlighter>
                                        </div>
                                    )}
                                </div>

                                {/* Action Bar */}
                                <div className="px-5 py-4 bg-[#0F172A]/50 border-t border-slate-700/50 flex items-center justify-between">
                                    <div>
                                        <input
                                            type="text"
                                            placeholder="Add a comment (optional)..."
                                            value={comments[approval.id] || ''}
                                            onChange={e => setComments(prev => ({ ...prev, [approval.id]: e.target.value }))}
                                            className="bg-[#1E293B] border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 w-80"
                                        />
                                    </div>
                                    <div className="flex items-center space-x-3">
                                        <button
                                            disabled={isDeciding}
                                            onClick={() => setConfirmAction({ id: approval.id, approved: false })}
                                            className="flex items-center space-x-1.5 px-4 py-2 bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded-lg hover:bg-rose-500/20 transition-colors text-xs font-bold disabled:opacity-50"
                                        >
                                            <XCircle className="w-4 h-4" />
                                            <span>Deny</span>
                                        </button>
                                        <button
                                            disabled={isDeciding}
                                            onClick={() => setConfirmAction({ id: approval.id, approved: true })}
                                            className="flex items-center space-x-1.5 px-4 py-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg hover:bg-emerald-500/20 transition-colors text-xs font-bold disabled:opacity-50"
                                        >
                                            <CheckCircle className="w-4 h-4" />
                                            <span>Approve</span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Confirmation Modal */}
            {confirmAction && (
                <div className="fixed inset-0 bg-slate-900/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-[#0F172A] border border-slate-700 rounded-2xl w-full max-w-md shadow-2xl p-6">
                        <h3 className="text-lg font-bold text-white mb-3">
                            {confirmAction.approved ? 'Confirm Approval' : 'Confirm Denial'}
                        </h3>
                        <p className="text-sm text-slate-400 mb-6">
                            {confirmAction.approved
                                ? 'This will allow the generated code to execute in the sandbox. Are you sure?'
                                : 'This will reject the code and stop the investigation step. Are you sure?'}
                        </p>
                        <div className="flex justify-end space-x-3">
                            <button
                                onClick={() => setConfirmAction(null)}
                                className="px-4 py-2 rounded-lg text-slate-300 hover:bg-slate-800 transition-colors text-sm font-medium"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={() => handleDecide(confirmAction.id, confirmAction.approved)}
                                className={`flex items-center px-4 py-2 rounded-lg text-white text-sm font-medium transition-colors ${
                                    confirmAction.approved
                                        ? 'bg-emerald-600 hover:bg-emerald-500'
                                        : 'bg-rose-600 hover:bg-rose-500'
                                }`}
                            >
                                {decidingIds.has(confirmAction.id) && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />}
                                {confirmAction.approved ? 'Yes, Approve' : 'Yes, Deny'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
