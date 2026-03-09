import { useState } from 'react';
import { X, ChevronDown, ChevronUp, Copy, Check, CheckCircle, XCircle, Clock3, Loader2 } from 'lucide-react';
import type { WorkflowStep } from '../types';
import { STEP_LABELS } from '../types';

interface StepDetailPanelProps {
    step: WorkflowStep | null;
    onClose: () => void;
}

const statusConfig = {
    pending: { label: 'Pending', icon: Clock3, color: 'bg-slate-500/10 text-slate-400 border-slate-500/20' },
    running: { label: 'Running', icon: Loader2, color: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20', spin: true },
    completed: { label: 'Completed', icon: CheckCircle, color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
    failed: { label: 'Failed', icon: XCircle, color: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
} as const;

const formatDuration = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
};

function CollapsibleSection({
    title,
    defaultOpen = true,
    children,
    copyValue,
}: {
    title: string;
    defaultOpen?: boolean;
    children: React.ReactNode;
    copyValue?: string;
}) {
    const [open, setOpen] = useState(defaultOpen);
    const [copied, setCopied] = useState(false);

    const handleCopy = async (e: React.MouseEvent) => {
        e.stopPropagation();
        if (!copyValue) return;
        try {
            await navigator.clipboard.writeText(copyValue);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // clipboard may not be available
        }
    };

    return (
        <div className="border border-slate-700/50 rounded-lg overflow-hidden">
            <button
                className="w-full flex items-center justify-between px-4 py-3 bg-[#1E293B]/50 hover:bg-[#1E293B] transition-colors text-sm text-slate-300 font-medium"
                onClick={() => setOpen(prev => !prev)}
            >
                <div className="flex items-center gap-2">
                    {open ? (
                        <ChevronUp className="w-4 h-4 text-slate-500" />
                    ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500" />
                    )}
                    {title}
                </div>
                {copyValue && (
                    <button
                        className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                        onClick={handleCopy}
                    >
                        {copied ? (
                            <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                            </>
                        ) : (
                            <>
                                <Copy className="w-3 h-3" />
                                Copy JSON
                            </>
                        )}
                    </button>
                )}
            </button>
            {open && (
                <div className="px-4 py-3">
                    {children}
                </div>
            )}
        </div>
    );
}

export default function StepDetailPanel({ step, onClose }: StepDetailPanelProps) {
    const isVisible = step !== null;

    const label = step ? (STEP_LABELS[step.name] || step.name) : '';
    const cfg = step ? statusConfig[step.status] : statusConfig.pending;
    const StatusIcon = cfg.icon;

    const inputJson = step?.input ? JSON.stringify(step.input, null, 2) : null;
    const outputJson = step?.output ? JSON.stringify(step.output, null, 2) : null;

    const hasGuardrail = step?.guardrail_score != null;
    const guardrailPassed = hasGuardrail && step!.guardrail_threshold != null
        ? step!.guardrail_score! >= step!.guardrail_threshold!
        : hasGuardrail;
    const guardrailPct = hasGuardrail
        ? Math.min(Math.round(step!.guardrail_score! * 100), 100)
        : 0;
    const thresholdPct = step?.guardrail_threshold != null
        ? Math.min(Math.round(step.guardrail_threshold * 100), 100)
        : null;

    return (
        <div
            className={`fixed top-0 right-0 h-full w-[500px] z-50 bg-[#0F172A] border-l border-slate-700 shadow-2xl
                transform transition-transform duration-300 ease-in-out
                ${isVisible ? 'translate-x-0' : 'translate-x-full'}
            `}
        >
            {step && (
                <div className="flex flex-col h-full">
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/50">
                        <div className="flex items-center gap-3 min-w-0">
                            <h2 className="text-white font-semibold text-lg truncate">{label}</h2>
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${cfg.color}`}>
                                <StatusIcon className={`w-3 h-3 ${'spin' in cfg && cfg.spin ? 'animate-spin' : ''}`} />
                                {cfg.label}
                            </span>
                        </div>
                        <button
                            onClick={onClose}
                            className="text-slate-400 hover:text-white transition-colors p-1 rounded hover:bg-slate-700/50"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    {/* Body */}
                    <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
                        {/* Metadata badges */}
                        <div className="flex flex-wrap items-center gap-2">
                            {step.duration_ms != null && (
                                <span className="inline-flex items-center gap-1.5 bg-slate-700/50 text-slate-300 text-xs px-2.5 py-1 rounded">
                                    <Clock3 className="w-3 h-3" />
                                    {formatDuration(step.duration_ms)}
                                </span>
                            )}
                            {step.model_name && (
                                <span className="bg-cyan-500/10 text-cyan-400 text-xs px-2.5 py-1 rounded">
                                    {step.model_name}
                                </span>
                            )}
                            {step.retry_count != null && step.retry_count > 0 && (
                                <span className="text-xs text-amber-400 bg-amber-500/10 px-2.5 py-1 rounded border border-amber-500/20">
                                    {step.retry_count} {step.retry_count === 1 ? 'retry' : 'retries'}
                                </span>
                            )}
                        </div>

                        {/* Guardrail score */}
                        {hasGuardrail && (
                            <div className="space-y-2">
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-slate-400">Guardrail Score</span>
                                    <span className={`font-medium ${guardrailPassed ? 'text-emerald-400' : 'text-rose-400'}`}>
                                        {guardrailPct}%
                                        {thresholdPct != null && (
                                            <span className="text-slate-500 font-normal ml-1">
                                                / {thresholdPct}% threshold
                                            </span>
                                        )}
                                    </span>
                                </div>
                                <div className="relative w-full h-2.5 bg-slate-700/50 rounded-full overflow-hidden">
                                    <div
                                        className={`h-full rounded-full transition-all duration-500 ${guardrailPassed ? 'bg-emerald-500' : 'bg-rose-500'}`}
                                        style={{ width: `${guardrailPct}%` }}
                                    />
                                    {thresholdPct != null && (
                                        <div
                                            className="absolute top-0 h-full w-0.5 bg-slate-300/50"
                                            style={{ left: `${thresholdPct}%` }}
                                        />
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Error section */}
                        {step.error && (
                            <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4">
                                <p className="text-sm font-medium text-rose-400 mb-1">Error</p>
                                <p className="text-sm text-rose-300/80 whitespace-pre-wrap break-words">
                                    {step.error}
                                </p>
                            </div>
                        )}

                        {/* Input JSON */}
                        {inputJson && (
                            <CollapsibleSection
                                title="Input"
                                defaultOpen={true}
                                copyValue={inputJson}
                            >
                                <pre className="bg-[#1E293B] rounded p-4 text-sm text-slate-300 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap break-words">
                                    {inputJson}
                                </pre>
                            </CollapsibleSection>
                        )}

                        {/* Output JSON */}
                        {outputJson && (
                            <CollapsibleSection
                                title="Output"
                                defaultOpen={true}
                                copyValue={outputJson}
                            >
                                <pre className="bg-[#1E293B] rounded p-4 text-sm text-slate-300 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap break-words">
                                    {outputJson}
                                </pre>
                            </CollapsibleSection>
                        )}

                        {/* Timestamps */}
                        {(step.started_at || step.completed_at) && (
                            <div className="border border-slate-700/50 rounded-lg p-4 space-y-2 text-xs text-slate-500">
                                {step.started_at && (
                                    <div className="flex justify-between">
                                        <span>Started</span>
                                        <span className="text-slate-400">{new Date(step.started_at).toLocaleString()}</span>
                                    </div>
                                )}
                                {step.completed_at && (
                                    <div className="flex justify-between">
                                        <span>Completed</span>
                                        <span className="text-slate-400">{new Date(step.completed_at).toLocaleString()}</span>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
