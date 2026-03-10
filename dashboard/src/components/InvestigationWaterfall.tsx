import { Clock3, Loader2, CheckCircle, XCircle } from 'lucide-react';
import type { WorkflowStep } from '../types';
import { STEP_LABELS } from '../types';
import DataFlowBadge from './DataFlowBadge';

interface InvestigationWaterfallProps {
    steps: WorkflowStep[];
    isDemo?: boolean;
    onStepClick?: (step: WorkflowStep) => void;
}

const statusIcon = (status: WorkflowStep['status']) => {
    switch (status) {
        case 'pending':
            return <Clock3 className="w-5 h-5 text-slate-500" />;
        case 'running':
            return <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />;
        case 'completed':
            return <CheckCircle className="w-5 h-5 text-emerald-400" />;
        case 'failed':
            return <XCircle className="w-5 h-5 text-rose-400" />;
    }
};

const formatDuration = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
};

export default function InvestigationWaterfall({ steps, isDemo, onStepClick }: InvestigationWaterfallProps) {
    const completedCount = steps.filter(s => s.status === 'completed').length;
    const failedCount = steps.filter(s => s.status === 'failed').length;
    const finishedCount = completedCount + failedCount;
    const progressPct = steps.length > 0 ? Math.round((finishedCount / steps.length) * 100) : 0;

    return (
        <div className="space-y-4">
            {/* Progress bar */}
            <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-400">
                        Investigation Progress
                        {isDemo && (
                            <span className="ml-2 text-xs text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20">
                                Demo
                            </span>
                        )}
                    </span>
                    <span className="text-white font-medium">{progressPct}%</span>
                </div>
                <div className="w-full h-2 bg-slate-700/50 rounded-full overflow-hidden">
                    <div
                        className="h-full bg-cyan-500 rounded-full transition-all duration-500 ease-out"
                        style={{ width: `${progressPct}%` }}
                    />
                </div>
            </div>

            {/* Timeline */}
            <div className="relative space-y-0">
                {steps.map((step, idx) => {
                    const isLast = idx === steps.length - 1;
                    const label = STEP_LABELS[step.name] || step.name;
                    const isRunning = step.status === 'running';
                    const isCompleted = step.status === 'completed';
                    const isFailed = step.status === 'failed';
                    const isFinished = isCompleted || isFailed;

                    return (
                        <div key={step.id} className="relative flex items-stretch">
                            {/* Vertical line + icon column */}
                            <div className="flex flex-col items-center w-10 flex-shrink-0">
                                {/* Icon circle */}
                                <div className="z-10 flex items-center justify-center w-10 h-10 rounded-full bg-[#0F172A]">
                                    {statusIcon(step.status)}
                                </div>
                                {/* Connecting line */}
                                {!isLast && (
                                    <div
                                        className={`flex-1 w-px ${isFinished ? 'bg-slate-600' : 'border-l border-dashed border-slate-600'}`}
                                        style={{ minHeight: '16px' }}
                                    />
                                )}
                            </div>

                            {/* Step card */}
                            <div
                                className={`flex-1 ml-3 mb-3 p-4 rounded-lg border cursor-pointer transition-all
                                    bg-[#1E293B] border-slate-700/50
                                    hover:border-slate-600 hover:bg-[#1E293B]/80
                                    ${isRunning ? 'ring-1 ring-cyan-500/30' : ''}
                                `}
                                onClick={() => onStepClick?.(step)}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2 min-w-0">
                                        <span className="text-white text-sm font-medium truncate">
                                            {label}
                                        </span>
                                        {step.retry_count != null && step.retry_count > 0 && (
                                            <span className="text-xs text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded">
                                                retry {step.retry_count}
                                            </span>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                                        {step.execution_context && (
                                            <DataFlowBadge context={step.execution_context} />
                                        )}
                                        {step.model_name && (
                                            <span className="bg-cyan-500/10 text-cyan-400 text-xs px-2 py-0.5 rounded">
                                                {step.model_name}
                                            </span>
                                        )}
                                        {isFinished && step.duration_ms != null && (
                                            <span className="bg-slate-700/50 text-slate-400 text-xs px-2 py-0.5 rounded">
                                                {formatDuration(step.duration_ms)}
                                            </span>
                                        )}
                                    </div>
                                </div>

                                {/* Error preview */}
                                {isFailed && step.error && (
                                    <p className="mt-2 text-xs text-rose-400 truncate">
                                        {step.error}
                                    </p>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
