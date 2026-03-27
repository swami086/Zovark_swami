import { useEffect, useState } from 'react';
import { DollarSign, TrendingUp, Cpu, Activity, BarChart3 } from 'lucide-react';
import { fetchCosts, type CostData } from '../api/client';
import { Skeleton, CardSkeleton } from '../components/Skeleton';

const formatCurrency = (val: number) => {
    if (val >= 1) return `$${val.toFixed(2)}`;
    if (val >= 0.01) return `$${val.toFixed(3)}`;
    return `$${val.toFixed(4)}`;
};

const formatNumber = (val: number) => {
    if (val >= 1_000_000) return `${(val / 1_000_000).toFixed(1)}M`;
    if (val >= 1_000) return `${(val / 1_000).toFixed(1)}K`;
    return String(val);
};

type Period = 'daily' | 'weekly' | 'monthly';

const BarChart = ({ data, maxVal, colorClass }: { data: Array<{ label: string; value: number }>; maxVal: number; colorClass: string }) => (
    <div className="space-y-2">
        {data.map(item => (
            <div key={item.label} className="flex items-center space-x-3">
                <span className="text-xs text-slate-400 w-28 truncate text-right font-mono">{item.label}</span>
                <div className="flex-1 h-6 bg-slate-800/50 rounded-md overflow-hidden relative">
                    <div
                        className={`h-full ${colorClass} rounded-md transition-all duration-500`}
                        style={{ width: maxVal > 0 ? `${Math.max((item.value / maxVal) * 100, 2)}%` : '2%' }}
                    />
                    <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-bold text-white/80">
                        {formatCurrency(item.value)}
                    </span>
                </div>
            </div>
        ))}
    </div>
);

export default function CostDashboard() {
    const [costData, setCostData] = useState<CostData | null>(null);
    const [loading, setLoading] = useState(true);
    const [period, setPeriod] = useState<Period>('daily');
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const load = async () => {
            try {
                setLoading(true);
                const data = await fetchCosts(period);
                setCostData(data);
            } catch (err: any) {
                setError(err.message || 'Failed to load cost data');
                // Generate demo data so the page is still useful
                setCostData({
                    total_cost: 127.45,
                    cost_by_model: {
                        'zovarc-fast': 45.20,
                        'zovarc-standard': 62.30,
                        'zovarc-reasoning': 19.95,
                    },
                    cost_by_tenant: {
                        'zovarc-dev': 52.10,
                        'acme-corp': 38.75,
                        'security-inc': 36.60,
                    },
                    daily_costs: [
                        { date: '2026-03-06', cost: 18.20 },
                        { date: '2026-03-07', cost: 22.15 },
                        { date: '2026-03-08', cost: 15.80 },
                        { date: '2026-03-09', cost: 24.30 },
                        { date: '2026-03-10', cost: 19.50 },
                        { date: '2026-03-11', cost: 14.90 },
                        { date: '2026-03-12', cost: 12.60 },
                    ],
                    weekly_costs: [
                        { week: 'W09', cost: 42.50 },
                        { week: 'W10', cost: 48.35 },
                        { week: 'W11', cost: 36.60 },
                    ],
                    monthly_costs: [
                        { month: '2026-01', cost: 98.20 },
                        { month: '2026-02', cost: 115.40 },
                        { month: '2026-03', cost: 127.45 },
                    ],
                    total_tokens_input: 2_450_000,
                    total_tokens_output: 890_000,
                    total_requests: 1_247,
                });
            } finally {
                setLoading(false);
            }
        };
        load();
    }, [period]);

    const getTimelineData = (): Array<{ label: string; value: number }> => {
        if (!costData) return [];
        switch (period) {
            case 'daily':
                return costData.daily_costs.map(d => ({ label: d.date.slice(5), value: d.cost }));
            case 'weekly':
                return costData.weekly_costs.map(w => ({ label: w.week, value: w.cost }));
            case 'monthly':
                return costData.monthly_costs.map(m => ({ label: m.month, value: m.cost }));
        }
    };

    const modelData = costData ? Object.entries(costData.cost_by_model).map(([label, value]) => ({ label, value })) : [];
    const tenantData = costData ? Object.entries(costData.cost_by_tenant).map(([label, value]) => ({ label, value })) : [];
    const timelineData = getTimelineData();
    const maxModel = Math.max(...modelData.map(d => d.value), 1);
    const maxTenant = Math.max(...tenantData.map(d => d.value), 1);
    const maxTimeline = Math.max(...timelineData.map(d => d.value), 1);

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white tracking-tight flex items-center">
                        <DollarSign className="w-6 h-6 mr-3 text-emerald-400" />
                        LLM Cost Tracking
                    </h1>
                    <p className="text-slate-400 mt-1">Monitor inference costs across models and tenants</p>
                </div>
                <div className="flex items-center bg-slate-800/50 border border-slate-700/50 rounded-lg p-1">
                    {(['daily', 'weekly', 'monthly'] as Period[]).map(p => (
                        <button
                            key={p}
                            onClick={() => setPeriod(p)}
                            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize ${
                                period === p
                                    ? 'bg-cyan-500/20 text-cyan-400'
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            {p}
                        </button>
                    ))}
                </div>
            </div>

            {error && (
                <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400 p-3 rounded-xl text-sm">
                    Using demo data. Connect your API to see real costs.
                </div>
            )}

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {loading || !costData ? (
                    Array.from({ length: 4 }).map((_, i) => <CardSkeleton key={i} />)
                ) : (
                    <>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <DollarSign className="w-4 h-4 mr-2 text-emerald-400" />
                                <span className="text-xs font-medium uppercase tracking-wider">Total Cost</span>
                            </div>
                            <p className="text-2xl font-bold text-emerald-400">{formatCurrency(costData.total_cost)}</p>
                        </div>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <Activity className="w-4 h-4 mr-2 text-cyan-400" />
                                <span className="text-xs font-medium uppercase tracking-wider">Total Requests</span>
                            </div>
                            <p className="text-2xl font-bold text-cyan-400">{formatNumber(costData.total_requests)}</p>
                        </div>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <TrendingUp className="w-4 h-4 mr-2 text-violet-400" />
                                <span className="text-xs font-medium uppercase tracking-wider">Input Tokens</span>
                            </div>
                            <p className="text-2xl font-bold text-violet-400">{formatNumber(costData.total_tokens_input)}</p>
                        </div>
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                            <div className="flex items-center text-slate-400 mb-2">
                                <Cpu className="w-4 h-4 mr-2 text-amber-400" />
                                <span className="text-xs font-medium uppercase tracking-wider">Output Tokens</span>
                            </div>
                            <p className="text-2xl font-bold text-amber-400">{formatNumber(costData.total_tokens_output)}</p>
                        </div>
                    </>
                )}
            </div>

            {/* Charts */}
            {loading || !costData ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                        <Skeleton className="h-5 w-32 mb-4" />
                        <div className="space-y-3">
                            {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-6 w-full" />)}
                        </div>
                    </div>
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                        <Skeleton className="h-5 w-32 mb-4" />
                        <div className="space-y-3">
                            {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-6 w-full" />)}
                        </div>
                    </div>
                </div>
            ) : (
                <>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Cost by Model */}
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                            <h3 className="text-sm font-bold text-slate-200 mb-4 flex items-center">
                                <BarChart3 className="w-4 h-4 mr-2 text-cyan-400" />
                                Cost by Model
                            </h3>
                            {modelData.length === 0 ? (
                                <p className="text-sm text-slate-500 text-center py-8">No model cost data available</p>
                            ) : (
                                <BarChart data={modelData} maxVal={maxModel} colorClass="bg-cyan-500" />
                            )}
                        </div>

                        {/* Cost by Tenant */}
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                            <h3 className="text-sm font-bold text-slate-200 mb-4 flex items-center">
                                <BarChart3 className="w-4 h-4 mr-2 text-violet-400" />
                                Cost by Tenant
                            </h3>
                            {tenantData.length === 0 ? (
                                <p className="text-sm text-slate-500 text-center py-8">No tenant cost data available</p>
                            ) : (
                                <BarChart data={tenantData} maxVal={maxTenant} colorClass="bg-violet-500" />
                            )}
                        </div>
                    </div>

                    {/* Timeline */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                        <h3 className="text-sm font-bold text-slate-200 mb-4 flex items-center">
                            <TrendingUp className="w-4 h-4 mr-2 text-emerald-400" />
                            {period.charAt(0).toUpperCase() + period.slice(1)} Cost Breakdown
                        </h3>
                        {timelineData.length === 0 ? (
                            <p className="text-sm text-slate-500 text-center py-8">No timeline data available</p>
                        ) : (
                            <BarChart data={timelineData} maxVal={maxTimeline} colorClass="bg-emerald-500" />
                        )}
                    </div>

                    {/* Cost per Request */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                        <h3 className="text-sm font-bold text-slate-200 mb-4">Cost Efficiency</h3>
                        <div className="grid grid-cols-3 gap-4">
                            <div className="bg-[#0F172A] rounded-lg p-4 border border-slate-700/50">
                                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Cost / Request</p>
                                <p className="text-lg font-bold text-white">
                                    {costData.total_requests > 0
                                        ? formatCurrency(costData.total_cost / costData.total_requests)
                                        : '-'}
                                </p>
                            </div>
                            <div className="bg-[#0F172A] rounded-lg p-4 border border-slate-700/50">
                                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Cost / 1K Input Tokens</p>
                                <p className="text-lg font-bold text-white">
                                    {costData.total_tokens_input > 0
                                        ? formatCurrency((costData.total_cost * 1000) / costData.total_tokens_input)
                                        : '-'}
                                </p>
                            </div>
                            <div className="bg-[#0F172A] rounded-lg p-4 border border-slate-700/50">
                                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Avg Tokens / Request</p>
                                <p className="text-lg font-bold text-white">
                                    {costData.total_requests > 0
                                        ? formatNumber(Math.round((costData.total_tokens_input + costData.total_tokens_output) / costData.total_requests))
                                        : '-'}
                                </p>
                            </div>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
