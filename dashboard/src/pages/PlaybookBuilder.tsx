import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Workflow, Plus, Trash2, GripVertical, ArrowLeft, Save, Loader2, X, ChevronUp, ChevronDown } from 'lucide-react';
import { createPlaybook } from '../api/client';

const ACTION_TYPES = [
    { value: 'isolate_host', label: 'Isolate Host', color: 'text-rose-400', desc: 'Quarantine a compromised endpoint' },
    { value: 'block_ip', label: 'Block IP', color: 'text-amber-400', desc: 'Add IP to firewall blocklist' },
    { value: 'disable_user', label: 'Disable User', color: 'text-orange-400', desc: 'Disable a compromised user account' },
    { value: 'scan_endpoint', label: 'Scan Endpoint', color: 'text-cyan-400', desc: 'Run AV/EDR scan on endpoint' },
    { value: 'notify_team', label: 'Notify Team', color: 'text-blue-400', desc: 'Send alert to SOC team' },
    { value: 'create_ticket', label: 'Create Ticket', color: 'text-violet-400', desc: 'Create incident ticket in ITSM' },
    { value: 'collect_forensics', label: 'Collect Forensics', color: 'text-emerald-400', desc: 'Gather forensic artifacts' },
];

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'informational'];
const VERDICT_OPTIONS = ['malicious', 'suspicious', 'benign', 'unknown'];
const ALERT_TYPE_OPTIONS = ['brute_force', 'c2_beacon', 'data_exfiltration', 'lateral_movement', 'phishing', 'ransomware', 'privilege_escalation'];

interface WorkflowStep {
    id: string;
    action_type: string;
    description: string;
    parameters: Record<string, string>;
}

interface Condition {
    field: string;
    operator: string;
    value: string;
}

export default function PlaybookBuilder() {
    const navigate = useNavigate();
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [taskType, setTaskType] = useState('incident_response');
    const [steps, setSteps] = useState<WorkflowStep[]>([]);
    const [conditions, setConditions] = useState<Condition[]>([]);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const addStep = (actionType: string) => {
        const action = ACTION_TYPES.find(a => a.value === actionType);
        setSteps(prev => [...prev, {
            id: `step-${Date.now()}`,
            action_type: actionType,
            description: action?.desc || '',
            parameters: {},
        }]);
    };

    const removeStep = (id: string) => {
        setSteps(prev => prev.filter(s => s.id !== id));
    };

    const moveStep = (idx: number, dir: -1 | 1) => {
        const newIdx = idx + dir;
        if (newIdx < 0 || newIdx >= steps.length) return;
        const newSteps = [...steps];
        [newSteps[idx], newSteps[newIdx]] = [newSteps[newIdx], newSteps[idx]];
        setSteps(newSteps);
    };

    const updateStepParam = (id: string, key: string, value: string) => {
        setSteps(prev => prev.map(s =>
            s.id === id ? { ...s, parameters: { ...s.parameters, [key]: value } } : s
        ));
    };

    const updateStepDescription = (id: string, desc: string) => {
        setSteps(prev => prev.map(s =>
            s.id === id ? { ...s, description: desc } : s
        ));
    };

    const addCondition = () => {
        setConditions(prev => [...prev, { field: 'severity', operator: 'equals', value: '' }]);
    };

    const updateCondition = (idx: number, field: keyof Condition, value: string) => {
        setConditions(prev => prev.map((c, i) => i === idx ? { ...c, [field]: value } : c));
    };

    const removeCondition = (idx: number) => {
        setConditions(prev => prev.filter((_, i) => i !== idx));
    };

    const handleSave = async () => {
        if (!name.trim()) {
            setError('Playbook name is required');
            return;
        }
        if (steps.length === 0) {
            setError('Add at least one step');
            return;
        }
        setError(null);
        setSaving(true);
        try {
            // Convert steps to string prompts for the API
            const stepPrompts = steps.map((s, i) => {
                const params = Object.entries(s.parameters)
                    .filter(([, v]) => v)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join(', ');
                return `Step ${i + 1} [${s.action_type}]: ${s.description}${params ? ` (${params})` : ''}`;
            });

            const conditionStr = conditions.length > 0
                ? conditions.map(c => `${c.field} ${c.operator} ${c.value}`).join(' AND ')
                : undefined;

            await createPlaybook({
                name,
                description: description + (conditionStr ? `\nTrigger: ${conditionStr}` : ''),
                icon: '\u{1F6E1}',
                task_type: taskType,
                steps: stepPrompts.slice(0, 3), // API max 3 steps
                system_prompt_override: conditionStr ? `Auto-trigger conditions: ${conditionStr}` : undefined,
            });
            navigate('/playbooks');
        } catch (err: any) {
            setError(err.message || 'Failed to save playbook');
        } finally {
            setSaving(false);
        }
    };

    const getConditionValues = (field: string): string[] => {
        switch (field) {
            case 'severity': return SEVERITY_OPTIONS;
            case 'verdict': return VERDICT_OPTIONS;
            case 'alert_type': return ALERT_TYPE_OPTIONS;
            default: return [];
        }
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                    <button onClick={() => navigate('/playbooks')} className="p-2 -ml-2 rounded-full hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors">
                        <ArrowLeft className="w-5 h-5" />
                    </button>
                    <div>
                        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center">
                            <Workflow className="w-6 h-6 mr-3 text-cyan-500" />
                            Playbook Builder
                        </h1>
                        <p className="text-slate-400 mt-1">Build automated response workflows visually</p>
                    </div>
                </div>
                <button
                    onClick={handleSave}
                    disabled={saving}
                    className="flex items-center px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors font-medium shadow-lg shadow-cyan-900/20 disabled:opacity-50"
                >
                    {saving ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
                    {saving ? 'Saving...' : 'Save Playbook'}
                </button>
            </div>

            {error && (
                <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 p-3 rounded-xl text-sm">
                    {error}
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left: Playbook Config */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Basic Info */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6 space-y-4">
                        <h3 className="text-sm font-bold text-white">Playbook Details</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Name</label>
                                <input
                                    type="text" value={name} onChange={e => setName(e.target.value)}
                                    className="w-full bg-[#0F172A] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                    placeholder="e.g. Ransomware Response"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Task Type</label>
                                <select
                                    value={taskType} onChange={e => setTaskType(e.target.value)}
                                    className="w-full bg-[#0F172A] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                                >
                                    <option value="incident_response">Incident Response</option>
                                    <option value="log_analysis">Log Analysis</option>
                                    <option value="threat_hunt">Threat Hunt</option>
                                    <option value="code_audit">Code Audit</option>
                                    <option value="ioc_scan">IOC Scan</option>
                                </select>
                            </div>
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Description</label>
                            <textarea
                                rows={2} value={description} onChange={e => setDescription(e.target.value)}
                                className="w-full bg-[#0F172A] border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 resize-none"
                                placeholder="Describe what this playbook does..."
                            />
                        </div>
                    </div>

                    {/* Conditions */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-sm font-bold text-white">Trigger Conditions</h3>
                            <button
                                onClick={addCondition}
                                className="flex items-center text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
                            >
                                <Plus className="w-3.5 h-3.5 mr-1" /> Add Condition
                            </button>
                        </div>
                        {conditions.length === 0 ? (
                            <p className="text-sm text-slate-500 text-center py-4">No conditions. Playbook will be manually triggered.</p>
                        ) : (
                            <div className="space-y-3">
                                {conditions.map((cond, idx) => (
                                    <div key={idx} className="flex items-center space-x-3">
                                        {idx > 0 && <span className="text-xs text-slate-500 font-bold">AND</span>}
                                        <select
                                            value={cond.field}
                                            onChange={e => updateCondition(idx, 'field', e.target.value)}
                                            className="bg-[#0F172A] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                                        >
                                            <option value="severity">Severity</option>
                                            <option value="verdict">Verdict</option>
                                            <option value="alert_type">Alert Type</option>
                                        </select>
                                        <select
                                            value={cond.operator}
                                            onChange={e => updateCondition(idx, 'operator', e.target.value)}
                                            className="bg-[#0F172A] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                                        >
                                            <option value="equals">equals</option>
                                            <option value="not_equals">not equals</option>
                                            <option value="in">in</option>
                                        </select>
                                        <select
                                            value={cond.value}
                                            onChange={e => updateCondition(idx, 'value', e.target.value)}
                                            className="bg-[#0F172A] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 flex-1"
                                        >
                                            <option value="">Select value...</option>
                                            {getConditionValues(cond.field).map(v => (
                                                <option key={v} value={v}>{v}</option>
                                            ))}
                                        </select>
                                        <button onClick={() => removeCondition(idx)} className="text-slate-500 hover:text-rose-400 transition-colors">
                                            <X className="w-4 h-4" />
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Workflow Steps */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6">
                        <h3 className="text-sm font-bold text-white mb-4">Workflow Steps</h3>
                        {steps.length === 0 ? (
                            <div className="text-center py-8 border-2 border-dashed border-slate-700 rounded-xl">
                                <p className="text-sm text-slate-500 mb-2">No steps added yet</p>
                                <p className="text-xs text-slate-600">Select an action type from the panel on the right</p>
                            </div>
                        ) : (
                            <div className="space-y-3">
                                {steps.map((step, idx) => {
                                    const action = ACTION_TYPES.find(a => a.value === step.action_type);
                                    return (
                                        <div key={step.id} className="bg-[#0F172A] border border-slate-700/50 rounded-xl p-4">
                                            <div className="flex items-start space-x-3">
                                                {/* Reorder */}
                                                <div className="flex flex-col items-center space-y-1 pt-1">
                                                    <button onClick={() => moveStep(idx, -1)} disabled={idx === 0}
                                                        className="text-slate-500 hover:text-white disabled:opacity-30 transition-colors">
                                                        <ChevronUp className="w-4 h-4" />
                                                    </button>
                                                    <GripVertical className="w-4 h-4 text-slate-600" />
                                                    <button onClick={() => moveStep(idx, 1)} disabled={idx === steps.length - 1}
                                                        className="text-slate-500 hover:text-white disabled:opacity-30 transition-colors">
                                                        <ChevronDown className="w-4 h-4" />
                                                    </button>
                                                </div>

                                                {/* Step content */}
                                                <div className="flex-1">
                                                    <div className="flex items-center justify-between mb-2">
                                                        <div className="flex items-center space-x-2">
                                                            <span className="w-6 h-6 rounded-full bg-cyan-500/10 text-cyan-400 font-bold text-xs flex items-center justify-center border border-cyan-500/20">
                                                                {idx + 1}
                                                            </span>
                                                            <span className={`text-sm font-bold ${action?.color || 'text-white'}`}>
                                                                {action?.label || step.action_type}
                                                            </span>
                                                        </div>
                                                        <button onClick={() => removeStep(step.id)}
                                                            className="text-slate-500 hover:text-rose-400 transition-colors">
                                                            <Trash2 className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                    <input
                                                        type="text"
                                                        value={step.description}
                                                        onChange={e => updateStepDescription(step.id, e.target.value)}
                                                        className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 mb-2"
                                                        placeholder="Step description..."
                                                    />
                                                    {/* Parameter input based on action type */}
                                                    {(step.action_type === 'block_ip' || step.action_type === 'isolate_host') && (
                                                        <input
                                                            type="text"
                                                            value={step.parameters.target || ''}
                                                            onChange={e => updateStepParam(step.id, 'target', e.target.value)}
                                                            className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                                                            placeholder={step.action_type === 'block_ip' ? 'Target IP (e.g. {{source_ip}})' : 'Hostname (e.g. {{hostname}})'}
                                                        />
                                                    )}
                                                    {step.action_type === 'disable_user' && (
                                                        <input
                                                            type="text"
                                                            value={step.parameters.username || ''}
                                                            onChange={e => updateStepParam(step.id, 'username', e.target.value)}
                                                            className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                                                            placeholder="Username (e.g. {{affected_user}})"
                                                        />
                                                    )}
                                                    {step.action_type === 'notify_team' && (
                                                        <input
                                                            type="text"
                                                            value={step.parameters.channel || ''}
                                                            onChange={e => updateStepParam(step.id, 'channel', e.target.value)}
                                                            className="w-full bg-[#1E293B] border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                                                            placeholder="Notification channel (e.g. #soc-alerts)"
                                                        />
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>

                {/* Right: Action Palette */}
                <div className="space-y-4">
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                        <h3 className="text-sm font-bold text-white mb-3">Action Types</h3>
                        <p className="text-xs text-slate-500 mb-4">Click to add to workflow</p>
                        <div className="space-y-2">
                            {ACTION_TYPES.map(action => (
                                <button
                                    key={action.value}
                                    onClick={() => addStep(action.value)}
                                    className="w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg bg-[#0F172A] border border-slate-700/50 hover:border-cyan-500/30 hover:bg-slate-800/50 transition-all text-left group"
                                >
                                    <Plus className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors flex-shrink-0" />
                                    <div className="flex-1 min-w-0">
                                        <p className={`text-xs font-bold ${action.color}`}>{action.label}</p>
                                        <p className="text-[10px] text-slate-500 truncate">{action.desc}</p>
                                    </div>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Step Count */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5">
                        <h3 className="text-sm font-bold text-white mb-2">Summary</h3>
                        <div className="space-y-2 text-xs">
                            <div className="flex justify-between">
                                <span className="text-slate-400">Total Steps</span>
                                <span className="font-bold text-white">{steps.length}</span>
                            </div>
                            <div className="flex justify-between">
                                <span className="text-slate-400">Conditions</span>
                                <span className="font-bold text-white">{conditions.length}</span>
                            </div>
                            <div className="flex justify-between">
                                <span className="text-slate-400">Task Type</span>
                                <span className="font-bold text-white capitalize">{taskType.replace(/_/g, ' ')}</span>
                            </div>
                        </div>
                    </div>

                    {/* Tips */}
                    <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-xl p-5">
                        <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">Tips</h3>
                        <ul className="text-[11px] text-slate-400 space-y-1.5">
                            <li>Use {'{{variable}}'} syntax for dynamic values</li>
                            <li>Steps execute sequentially top to bottom</li>
                            <li>Reorder steps with the up/down arrows</li>
                            <li>Max 3 steps per playbook (API limit)</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    );
}
