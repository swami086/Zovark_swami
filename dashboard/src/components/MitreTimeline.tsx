import { Shield, Clock3 } from 'lucide-react';
import type { InvestigationStep } from '../api/client';

interface MitreTimelineProps {
    steps: InvestigationStep[];
    taskType: string;
}

// MITRE ATT&CK tactic colors
const TACTIC_COLORS: Record<string, { bg: string; border: string; text: string; dot: string }> = {
    'Initial Access': { bg: 'bg-rose-500/10', border: 'border-rose-500/20', text: 'text-rose-400', dot: 'bg-rose-500' },
    'Execution': { bg: 'bg-orange-500/10', border: 'border-orange-500/20', text: 'text-orange-400', dot: 'bg-orange-500' },
    'Persistence': { bg: 'bg-amber-500/10', border: 'border-amber-500/20', text: 'text-amber-400', dot: 'bg-amber-500' },
    'Privilege Escalation': { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', text: 'text-yellow-400', dot: 'bg-yellow-500' },
    'Defense Evasion': { bg: 'bg-lime-500/10', border: 'border-lime-500/20', text: 'text-lime-400', dot: 'bg-lime-500' },
    'Credential Access': { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400', dot: 'bg-emerald-500' },
    'Discovery': { bg: 'bg-teal-500/10', border: 'border-teal-500/20', text: 'text-teal-400', dot: 'bg-teal-500' },
    'Lateral Movement': { bg: 'bg-cyan-500/10', border: 'border-cyan-500/20', text: 'text-cyan-400', dot: 'bg-cyan-500' },
    'Collection': { bg: 'bg-blue-500/10', border: 'border-blue-500/20', text: 'text-blue-400', dot: 'bg-blue-500' },
    'Command and Control': { bg: 'bg-indigo-500/10', border: 'border-indigo-500/20', text: 'text-indigo-400', dot: 'bg-indigo-500' },
    'Exfiltration': { bg: 'bg-violet-500/10', border: 'border-violet-500/20', text: 'text-violet-400', dot: 'bg-violet-500' },
    'Impact': { bg: 'bg-purple-500/10', border: 'border-purple-500/20', text: 'text-purple-400', dot: 'bg-purple-500' },
    'Detection': { bg: 'bg-sky-500/10', border: 'border-sky-500/20', text: 'text-sky-400', dot: 'bg-sky-500' },
    'Response': { bg: 'bg-fuchsia-500/10', border: 'border-fuchsia-500/20', text: 'text-fuchsia-400', dot: 'bg-fuchsia-500' },
};

// Map step types to MITRE techniques
const STEP_MITRE_MAP: Record<string, { tactic: string; technique: string; techniqueId: string }> = {
    'parse_alert': { tactic: 'Detection', technique: 'Alert Parsing', techniqueId: 'T1059' },
    'generate_python': { tactic: 'Execution', technique: 'Code Generation', techniqueId: 'T1059.006' },
    'generate_code': { tactic: 'Execution', technique: 'Code Generation', techniqueId: 'T1059.006' },
    'execute_sandbox': { tactic: 'Execution', technique: 'Sandbox Execution', techniqueId: 'T1204' },
    'execute_code': { tactic: 'Execution', technique: 'Sandbox Execution', techniqueId: 'T1204' },
    'extract_entities': { tactic: 'Discovery', technique: 'Entity Extraction', techniqueId: 'T1087' },
    'guardrail_check': { tactic: 'Defense Evasion', technique: 'Quality Validation', techniqueId: 'T1027' },
    'validate_generated_code': { tactic: 'Defense Evasion', technique: 'Code Validation', techniqueId: 'T1027' },
    'generate_report': { tactic: 'Collection', technique: 'Report Generation', techniqueId: 'T1119' },
    'generate_incident_report': { tactic: 'Collection', technique: 'Incident Report', techniqueId: 'T1119' },
    'analysis': { tactic: 'Discovery', technique: 'Log Analysis', techniqueId: 'T1046' },
    'enrichment': { tactic: 'Collection', technique: 'Data Enrichment', techniqueId: 'T1213' },
    'deep_analysis': { tactic: 'Discovery', technique: 'Deep Analysis', techniqueId: 'T1046' },
};

// Additional task-type based mapping
const TASK_TYPE_TACTICS: Record<string, string> = {
    'log_analysis': 'Detection',
    'threat_hunt': 'Discovery',
    'incident_response': 'Response',
    'code_audit': 'Initial Access',
    'ioc_scan': 'Collection',
};

function getMitreForStep(step: InvestigationStep, taskType: string) {
    const stepKey = step.step_type?.toLowerCase().replace(/ /g, '_') || '';
    if (STEP_MITRE_MAP[stepKey]) return STEP_MITRE_MAP[stepKey];

    // Infer from task type
    const tactic = TASK_TYPE_TACTICS[taskType?.toLowerCase().replace(/ /g, '_')] || 'Discovery';
    return { tactic, technique: step.step_type || 'Analysis', techniqueId: 'T1046' };
}

const DEFAULT_COLORS = TACTIC_COLORS['Detection'];

export default function MitreTimeline({ steps, taskType }: MitreTimelineProps) {
    if (!steps || steps.length === 0) {
        return null;
    }

    // Collect unique tactics used
    const tacticsUsed = new Set<string>();
    steps.forEach(step => {
        const mitre = getMitreForStep(step, taskType);
        tacticsUsed.add(mitre.tactic);
    });

    return (
        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
            <h3 className="text-sm font-bold text-white mb-4 flex items-center">
                <Shield className="w-4 h-4 mr-2 text-cyan-400" />
                MITRE ATT&CK Timeline
            </h3>

            {/* Tactic Legend */}
            <div className="flex flex-wrap gap-2 mb-4">
                {Array.from(tacticsUsed).map(tactic => {
                    const colors = TACTIC_COLORS[tactic] || DEFAULT_COLORS;
                    return (
                        <span key={tactic} className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${colors.bg} ${colors.border} ${colors.text}`}>
                            <span className={`w-1.5 h-1.5 rounded-full mr-1 ${colors.dot}`} />
                            {tactic}
                        </span>
                    );
                })}
            </div>

            {/* Timeline */}
            <div className="relative">
                {steps.map((step, idx) => {
                    const mitre = getMitreForStep(step, taskType);
                    const colors = TACTIC_COLORS[mitre.tactic] || DEFAULT_COLORS;
                    const isLast = idx === steps.length - 1;
                    const isCompleted = step.status === 'completed';
                    const isFailed = step.status === 'failed';

                    return (
                        <div key={step.id} className="flex relative">
                            {/* Timeline column */}
                            <div className="flex flex-col items-center w-8 flex-shrink-0">
                                <div className={`w-4 h-4 rounded-full border-2 z-10 ${
                                    isCompleted ? `${colors.dot} border-transparent` :
                                    isFailed ? 'bg-rose-500 border-transparent' :
                                    `bg-[#0F172A] ${colors.border}`
                                }`} />
                                {!isLast && (
                                    <div className={`flex-1 w-px ${isCompleted ? 'bg-slate-600' : 'border-l border-dashed border-slate-600'}`} style={{ minHeight: '20px' }} />
                                )}
                            </div>

                            {/* Content */}
                            <div className="flex-1 ml-2 mb-4 pb-1">
                                <div className="flex items-center space-x-2 mb-1">
                                    <span className={`text-xs font-bold ${colors.text}`}>{mitre.tactic}</span>
                                    <span className="text-[10px] text-slate-600">|</span>
                                    <span className="text-xs text-slate-400">{mitre.technique}</span>
                                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${colors.bg} ${colors.text} border ${colors.border}`}>
                                        {mitre.techniqueId}
                                    </span>
                                </div>
                                <div className="flex items-center space-x-3">
                                    <span className="text-xs text-slate-300 font-medium">
                                        Step {step.step_number}: {step.step_type}
                                    </span>
                                    {step.execution_ms && (
                                        <span className="flex items-center text-[10px] text-slate-500">
                                            <Clock3 className="w-3 h-3 mr-0.5" />
                                            {step.execution_ms > 1000 ? `${(step.execution_ms / 1000).toFixed(1)}s` : `${step.execution_ms}ms`}
                                        </span>
                                    )}
                                    <span className={`text-[10px] font-bold uppercase ${
                                        isCompleted ? 'text-emerald-400' : isFailed ? 'text-rose-400' : 'text-slate-500'
                                    }`}>
                                        {step.status}
                                    </span>
                                </div>
                                {step.prompt && (
                                    <p className="text-[11px] text-slate-500 mt-1 truncate max-w-md">{step.prompt}</p>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
