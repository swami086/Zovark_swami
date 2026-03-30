import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchTaskDetail, fetchTaskTimeline, fetchTaskSteps, decideApproval, type TaskDetail as TaskDetailType, type TimelineEvent, type InvestigationStep, getUser } from '../api/client';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Loader2, ArrowLeft, Terminal, FileCode2, Clock3, Cpu, DollarSign, ListFilter, CheckCircle, Copy, Check, ShieldAlert, Crosshair, AlertTriangle, Info, ListChecks, Target, CheckSquare, ChevronDown, ChevronUp, ChevronRight, Circle, Zap, ShieldCheck, XCircle, MessageSquare, Share2, FileJson } from 'lucide-react';
import { Skeleton } from '../components/Skeleton';
import MitreTimeline from '../components/MitreTimeline';

const StatusBadge = ({ status }: { status: string }) => {
    switch (status) {
        case 'completed':
            return (
                <span className="inline-flex items-center px-4 py-1.5 rounded-full text-sm font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm">
                    <span className="w-2 h-2 rounded-full bg-cyan-500 mr-2"></span>Resolved
                </span>
            );
        case 'failed':
            return (
                <span className="inline-flex items-center px-4 py-1.5 rounded-full text-sm font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 shadow-sm">
                    <span className="w-2 h-2 rounded-full bg-rose-500 mr-2"></span>Failed
                </span>
            );
        case 'executing':
            return (
                <span className="inline-flex items-center px-4 py-1.5 rounded-full text-sm font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 shadow-sm">
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />Analyzing
                </span>
            );
        case 'awaiting_approval':
            return (
                <span className="inline-flex items-center px-4 py-1.5 rounded-full text-sm font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 shadow-sm animate-pulse">
                    <span className="w-2 h-2 rounded-full bg-amber-500 mr-2"></span>Awaiting Approval
                </span>
            );
        case 'rejected':
            return (
                <span className="inline-flex items-center px-4 py-1.5 rounded-full text-sm font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20 shadow-sm">
                    <span className="w-2 h-2 rounded-full bg-purple-500 mr-2"></span>Rejected
                </span>
            );
        default:
            return (
                <span className="inline-flex items-center px-4 py-1.5 rounded-full text-sm font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20 shadow-sm">
                    <span className="w-2 h-2 rounded-full bg-slate-500 mr-2"></span>Pending
                </span>
            );
    }
};

const MITRE_MAPPING: Record<string, { tactic: string, tacticId: string, technique: string, techniqueId: string }> = {
    "log_analysis": { tactic: "Detection", tacticId: "TA0040", technique: "Log Analysis", techniqueId: "T1530" },
    "threat_hunt": { tactic: "Discovery", tacticId: "TA0007", technique: "Network Service Scanning", techniqueId: "T1046" },
    "incident_response": { tactic: "Response", tacticId: "TA0041", technique: "Incident Containment", techniqueId: "T1531" },
    "code_audit": { tactic: "Initial Access", tacticId: "TA0001", technique: "Exploit Public-Facing Application", techniqueId: "T1190" },
    "ioc_scan": { tactic: "Collection", tacticId: "TA0009", technique: "Indicator Scanning", techniqueId: "T1119" },
    "phishing_investigation": { tactic: "Initial Access", tacticId: "TA0001", technique: "Phishing", techniqueId: "T1566" },
    "ransomware_triage": { tactic: "Impact", tacticId: "TA0040", technique: "Data Encrypted for Impact", techniqueId: "T1486" },
    "brute_force_investigation": { tactic: "Credential Access", tacticId: "TA0006", technique: "Brute Force", techniqueId: "T1110" },
    "brute_force": { tactic: "Credential Access", tacticId: "TA0006", technique: "Brute Force", techniqueId: "T1110" },
    "c2_communication_hunt": { tactic: "Command and Control", tacticId: "TA0011", technique: "Application Layer Protocol", techniqueId: "T1071" },
    "data_exfiltration_detection": { tactic: "Exfiltration", tacticId: "TA0010", technique: "Exfiltration Over C2 Channel", techniqueId: "T1041" },
    "privilege_escalation_hunt": { tactic: "Privilege Escalation", tacticId: "TA0004", technique: "Exploitation for Privilege Escalation", techniqueId: "T1068" },
    "lateral_movement_detection": { tactic: "Lateral Movement", tacticId: "TA0008", technique: "Remote Services", techniqueId: "T1021" },
    "insider_threat_detection": { tactic: "Persistence", tacticId: "TA0003", technique: "Valid Accounts", techniqueId: "T1078" },
    "network_beaconing": { tactic: "Command and Control", tacticId: "TA0011", technique: "Web Protocols", techniqueId: "T1071.001" },
    "cloud_infrastructure_attack": { tactic: "Persistence", tacticId: "TA0003", technique: "Cloud Accounts", techniqueId: "T1078.004" },
    "supply_chain_compromise": { tactic: "Initial Access", tacticId: "TA0001", technique: "Supply Chain Compromise", techniqueId: "T1195" },
    "sql_injection": { tactic: "Initial Access", tacticId: "TA0001", technique: "Exploit Public-Facing Application", techniqueId: "T1190" },
    "xss": { tactic: "Initial Access", tacticId: "TA0001", technique: "Exploit Public-Facing Application", techniqueId: "T1190" },
    "directory_traversal": { tactic: "Discovery", tacticId: "TA0007", technique: "File and Directory Discovery", techniqueId: "T1083" },
    "authentication_bypass": { tactic: "Credential Access", tacticId: "TA0006", technique: "Exploitation for Credential Access", techniqueId: "T1212" },
};

// Full MITRE technique database for rendering output.mitre_attack
interface MitreTechnique {
    id: string;
    name: string;
    tactic: string;
}

const MITRE_TECHNIQUE_DB: Record<string, MitreTechnique[]> = {
    "phishing_investigation": [
        { id: "T1566", name: "Phishing", tactic: "Initial Access" },
        { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
        { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access" },
        { id: "T1204.001", name: "Malicious Link", tactic: "Execution" },
    ],
    "ransomware_triage": [
        { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
        { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
        { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
        { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence" },
    ],
    "brute_force_investigation": [
        { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
        { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
        { id: "T1110.003", name: "Password Spraying", tactic: "Credential Access" },
    ],
    "brute_force": [
        { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
        { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
        { id: "T1110.003", name: "Password Spraying", tactic: "Credential Access" },
    ],
    "c2_communication_hunt": [
        { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
        { id: "T1573", name: "Encrypted Channel", tactic: "Command and Control" },
        { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
        { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
    ],
    "data_exfiltration_detection": [
        { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
        { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
        { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
    ],
    "privilege_escalation_hunt": [
        { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
        { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
        { id: "T1134", name: "Access Token Manipulation", tactic: "Privilege Escalation" },
    ],
    "lateral_movement_detection": [
        { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
        { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
        { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement" },
    ],
    "insider_threat_detection": [
        { id: "T1078", name: "Valid Accounts", tactic: "Persistence" },
        { id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" },
        { id: "T1213", name: "Data from Information Repositories", tactic: "Collection" },
    ],
    "network_beaconing": [
        { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
        { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
        { id: "T1573.001", name: "Symmetric Cryptography", tactic: "Command and Control" },
    ],
    "cloud_infrastructure_attack": [
        { id: "T1078.004", name: "Cloud Accounts", tactic: "Persistence" },
        { id: "T1580", name: "Cloud Infrastructure Discovery", tactic: "Discovery" },
        { id: "T1537", name: "Transfer Data to Cloud Account", tactic: "Exfiltration" },
    ],
    "supply_chain_compromise": [
        { id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access" },
        { id: "T1195.002", name: "Compromise Software Supply Chain", tactic: "Initial Access" },
        { id: "T1195.001", name: "Compromise Software Dependencies", tactic: "Initial Access" },
    ],
};

const getMitreTechniques = (taskType: string, outputMitre?: MitreTechnique[]): MitreTechnique[] => {
    if (outputMitre && outputMitre.length > 0) return outputMitre;
    const key = (taskType || '').toLowerCase().replace(/ /g, '_').replace(/-/g, '_');
    if (MITRE_TECHNIQUE_DB[key]) return MITRE_TECHNIQUE_DB[key];
    for (const [k, v] of Object.entries(MITRE_TECHNIQUE_DB)) {
        if (k.includes(key) || key.includes(k)) return v;
    }
    return [];
};

const getMitreAttackUrl = (techniqueId: string): string => {
    const path = techniqueId.replace(/\./g, '/');
    return `https://attack.mitre.org/techniques/${path}/`;
};

const IOCConfidenceBadge = ({ confidence }: { confidence?: string }) => {
    if (!confidence) return null;
    const c = confidence.toLowerCase();
    if (c === 'high') {
        return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/25">HIGH</span>;
    }
    if (c === 'medium') {
        return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/25">MED</span>;
    }
    return <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-500/15 text-slate-400 border border-slate-500/25">LOW</span>;
};

const getMitreMapping = (taskType: string) => {
    const key = (taskType || '').toLowerCase().replace(/ /g, '_');
    return MITRE_MAPPING[key] || { tactic: "Discovery", tacticId: "TA0007", technique: "Network Service Scanning", techniqueId: "T1046" };
};

const SeverityBadge = ({ severity }: { severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational' }) => {
    const s = severity?.toLowerCase() || 'medium';
    let colorClass = "bg-amber-500/10 text-amber-400 border-amber-500/20";
    let dotClass = "bg-amber-400";

    if (s === 'critical' || s === 'high') {
        colorClass = "bg-rose-500/10 text-rose-400 border-rose-500/20";
        dotClass = "bg-rose-400";
    } else if (s === 'low') {
        colorClass = "bg-blue-500/10 text-blue-400 border-blue-500/20";
        dotClass = "bg-blue-400";
    } else if (s === 'informational') {
        colorClass = "bg-slate-500/10 text-slate-400 border-slate-500/20";
        dotClass = "bg-slate-400";
    }

    return (
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold border uppercase tracking-wider ${colorClass}`}>
            <span className={`w-2 h-2 rounded-full mr-1.5 ${dotClass}`}></span>
            {s}
        </span>
    );
};

const TaskDetail = () => {
    const { id } = useParams<{ id: string }>();
    const user = getUser();
    const [task, setTask] = useState<TaskDetailType | null>(null);
    const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [showRawJson, setShowRawJson] = useState(false);
    const [steps, setSteps] = useState<InvestigationStep[]>([]);
    const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({});
    const [showStepCode, setShowStepCode] = useState<Record<number, boolean>>({});
    const [showStepRawJson, setShowStepRawJson] = useState<Record<number, boolean>>({});
    const [showStepParams, setShowStepParams] = useState<Record<number, boolean>>({});
    const [approvalComment, setApprovalComment] = useState('');
    const [approvalSubmitting, setApprovalSubmitting] = useState(false);
    const [linkCopied, setLinkCopied] = useState(false);

    useEffect(() => {
        let interval: number;

        const loadTask = async () => {
            try {
                if (!id) return;
                const data = await fetchTaskDetail(id);
                setTask(data);
                document.title = `Investigation: ${data.id.split('-')[0]} | Zovark`;

                try {
                    const tlData = await fetchTaskTimeline(id);
                    setTimeline(tlData);
                } catch (e) {
                    console.error("Failed to fetch timeline data");
                }

                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                    // Fetch steps when task is finished
                    try {
                        const stepsData = await fetchTaskSteps(id);
                        setSteps(stepsData);
                        // Auto-expand the latest step
                        if (stepsData.length > 0) {
                            const latestStep = Math.max(...stepsData.map(s => s.step_number));
                            setExpandedSteps(prev => ({ ...prev, [latestStep]: true }));
                        }
                    } catch (e) {
                        console.error('Failed to fetch steps');
                    }
                }
            } catch (err: any) {
                setError(err.message || 'Failed to load investigation');
                clearInterval(interval);
            }
        };

        loadTask();
        interval = window.setInterval(loadTask, 2000);
        return () => clearInterval(interval);
    }, [id]);

    const handleCopy = () => {
        if (task?.output?.code) {
            navigator.clipboard.writeText(task.output.code);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        }
    };

    if (error) {
        return (
            <div className="text-center py-12">
                <p className="text-rose-400">{error}</p>
                <Link to="/" className="text-cyan-400 hover:text-cyan-300 mt-4 inline-block underline transition-colors">Back to Investigations</Link>
            </div>
        );
    }

    if (!task) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
            </div>
        );
    }

    const isFinished = task.status === 'completed' || task.status === 'failed';
    const INPUT_RATE = 0.15 / 1000000;
    const OUTPUT_RATE = 0.60 / 1000000;
    const inputCost = (task.tokens_used_input || 0) * INPUT_RATE;
    const outputCost = (task.tokens_used_output || 0) * OUTPUT_RATE;
    const totalCost = inputCost + outputCost;

    const exportPDF = () => {
        if (!task) return;
        const mitre = getMitreMapping(task.task_type);
        let parsedOutput: any = {};
        try { parsedOutput = task.output?.stdout ? JSON.parse(task.output.stdout) : {}; } catch { }
        const findings = parsedOutput.findings || [];
        const recommendations = parsedOutput.recommendations || [];
        const riskScore = parsedOutput.risk_score ?? '-';

        let stepsHTML = '';
        steps.forEach((s, i) => {
            let stepParsed: any = {};
            try { stepParsed = s.output ? JSON.parse(s.output) : {}; } catch { }
            const sf = stepParsed.findings || [];
            const sr = stepParsed.recommendations || [];
            stepsHTML += `<div class="step"><h3>Step ${i + 1}: ${s.step_type}</h3><p><strong>Prompt:</strong> ${s.prompt || '-'}</p>`;
            if (sf.length) { stepsHTML += '<h4>Findings</h4><ul>' + sf.map((f: any) => `<li><strong>${f.title || ''}</strong>: ${f.details || JSON.stringify(f)}</li>`).join('') + '</ul>'; }
            if (sr.length) { stepsHTML += '<h4>Recommendations</h4><ul>' + sr.map((r: any) => `<li>${r}</li>`).join('') + '</ul>'; }
            stepsHTML += '</div>';
        });

        const html = `<!DOCTYPE html><html><head><title>ZOVARK Investigation Report - ${task.id}</title>
<style>body{font-family:Arial,sans-serif;color:#1e293b;max-width:800px;margin:0 auto;padding:40px}
.cover{text-align:center;page-break-after:always;padding:100px 0}.cover h1{font-size:28px;color:#0e7490}
.cover .classification{background:#ef4444;color:#fff;display:inline-block;padding:4px 20px;font-weight:bold;letter-spacing:2px;margin:20px 0}
.cover .meta{margin-top:40px;color:#64748b;font-size:14px}.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:bold}
.severity-critical,.severity-high{background:#fef2f2;color:#ef4444}.severity-medium{background:#fffbeb;color:#f59e0b}
.severity-low{background:#eff6ff;color:#3b82f6;}.severity-informational{background:#f1f5f9;color:#64748b}
h2{color:#0e7490;border-bottom:2px solid #e2e8f0;padding-bottom:8px}h3{color:#334155}
.step{margin:16px 0;padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px}
ul{padding-left:20px}li{margin:4px 0}table{width:100%;border-collapse:collapse;margin:12px 0}
td,th{padding:8px 12px;border:1px solid #e2e8f0;text-align:left;font-size:13px}th{background:#f1f5f9}
@media print{.cover{page-break-after:always}.step{break-inside:avoid}}</style></head><body>
<div class="cover">
  <div class="classification">CONFIDENTIAL</div>
  <h1>ZOVARK Security Investigation Report</h1>
  <p style="font-size:18px;color:#0e7490">${task.task_type?.replace(/_/g, ' ').toUpperCase()}</p>
  <div class="meta">
    <p><strong>Investigation ID:</strong> ${task.id}</p>
    <p><strong>Date:</strong> ${new Date(task.created_at).toLocaleDateString()}</p>
    <p><strong>Status:</strong> ${task.status.toUpperCase()}</p>
    <p><span class="badge severity-${task.severity || 'medium'}">${(task.severity || 'medium').toUpperCase()}</span></p>
  </div>
</div>
<h2>Executive Summary</h2>
<p><strong>Investigation Brief:</strong> ${task.input?.prompt || '-'}</p>
<table><tr><th>Task Type</th><td>${task.task_type}</td></tr>
<tr><th>MITRE ATT&CK</th><td>${mitre.tactic} (${mitre.tacticId}) — ${mitre.technique} (${mitre.techniqueId})</td></tr>
<tr><th>Risk Score</th><td>${riskScore}/100</td></tr></table>
${findings.length ? '<h3>Key Findings</h3><ul>' + findings.slice(0, 5).map((f: any) => `<li><strong>${f.title || ''}</strong>: ${f.details || JSON.stringify(f)}</li>`).join('') + '</ul>' : ''}
${recommendations.length ? '<h3>Recommendations</h3><ul>' + recommendations.slice(0, 5).map((r: any) => `<li>${r}</li>`).join('') + '</ul>' : ''}
<h2>Investigation Steps (${steps.length})</h2>${stepsHTML || '<p>No steps recorded.</p>'}
<h2>Appendix</h2>
<table><tr><th>Tokens (In/Out)</th><td>${(task.tokens_used_input || 0).toLocaleString()} / ${(task.tokens_used_output || 0).toLocaleString()}</td></tr>
<tr><th>Cost</th><td>$${totalCost.toFixed(4)}</td></tr>
<tr><th>Duration</th><td>${task.execution_ms ? (task.execution_ms / 1000).toFixed(2) + 's' : '-'}</td></tr></table>
<p style="text-align:center;color:#94a3b8;margin-top:40px;font-size:12px">Generated by ZOVARK • ${new Date().toISOString()}</p>
</body></html>`;

        const w = window.open('', '_blank');
        if (w) { w.document.write(html); w.document.close(); w.print(); }
    };

    const handleCopyLink = () => {
        navigator.clipboard.writeText(window.location.href);
        setLinkCopied(true);
        setTimeout(() => setLinkCopied(false), 2000);
    };

    const exportJSON = () => {
        const data = JSON.stringify({
            task,
            steps,
            timeline
        }, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `zovark-investigation-${task.id}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    if (!task && !error) {
        return (
            <div className="space-y-6 max-w-[1200px] mx-auto animate-pulse">
                <div className="flex justify-between items-center mb-8 pb-6 border-b border-slate-700/50">
                    <div className="flex items-center space-x-4">
                        <Skeleton className="w-10 h-10 rounded-full" />
                        <div>
                            <Skeleton className="h-8 w-48 mb-2" />
                            <Skeleton className="h-4 w-64" />
                        </div>
                    </div>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
                    <div className="lg:col-span-3 space-y-6">
                        <Skeleton className="h-40 w-full rounded-xl" />
                        <Skeleton className="h-64 w-full rounded-xl" />
                    </div>
                    <div className="lg:col-span-2 space-y-6">
                        <Skeleton className="h-32 w-full rounded-xl" />
                        <Skeleton className="h-48 w-full rounded-xl" />
                    </div>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex flex-col items-center justify-center h-[60vh] text-center space-y-4">
                <div className="bg-rose-500/10 p-4 rounded-full">
                    <AlertTriangle className="w-12 h-12 text-rose-500" />
                </div>
                <h2 className="text-xl font-bold text-white">Investigation Not Found</h2>
                <p className="text-slate-400 max-w-md">{error}</p>
                <Link to="/tasks" className="px-6 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
                    Back to Investigations
                </Link>
            </div>
        );
    }

    return (
        <div className="space-y-6 max-w-[1200px] mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-8 pb-6 border-b border-slate-700/50">
                <div className="flex items-center space-x-4">
                    <Link to="/" className="p-2 -ml-2 rounded-full hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors">
                        <ArrowLeft className="w-5 h-5" />
                    </Link>
                    <div>
                        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center">
                            Investigation Analysis
                        </h1>
                        <p className="text-sm font-mono text-slate-400 mt-1.5">{task.id}</p>
                    </div>
                </div>
                <div className="flex items-center space-x-3">
                    <button onClick={handleCopyLink}
                        className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 text-slate-300 border border-slate-700/50 rounded-lg hover:bg-slate-700 transition-colors text-sm font-medium">
                        {linkCopied ? <Check className="w-4 h-4 text-emerald-400" /> : <Share2 className="w-4 h-4" />}
                        <span>{linkCopied ? 'Copied!' : 'Copy Link'}</span>
                    </button>
                    {isFinished && (
                        <>
                            <button onClick={exportJSON}
                                className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 text-slate-300 border border-slate-700/50 rounded-lg hover:bg-slate-700 transition-colors text-sm font-medium">
                                <FileJson className="w-4 h-4" />
                                <span>Export JSON</span>
                            </button>
                            <button onClick={exportPDF}
                                className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-lg hover:bg-cyan-500/20 transition-colors text-sm font-medium">
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                                <span>Download PDF</span>
                            </button>
                        </>
                    )}
                    {task.severity && <SeverityBadge severity={task.severity} />}
                    <StatusBadge status={task.status} />
                </div>
            </div>

            {/* Two Column Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">

                {/* Left Column (60%) */}
                <div className="lg:col-span-3 space-y-6">

                    {/* Approval Banner */}
                    {task.status === 'awaiting_approval' && task.pending_approval_id && (
                        <div className="bg-gradient-to-br from-amber-500/5 to-amber-600/5 border-2 border-amber-500/30 rounded-xl p-6 shadow-lg">
                            <div className="flex items-start space-x-4">
                                <div className="bg-amber-500/10 p-3 rounded-xl border border-amber-500/20">
                                    <ShieldAlert className="w-7 h-7 text-amber-400" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="text-lg font-bold text-amber-400 flex items-center">
                                        Approval Required
                                    </h3>
                                    <p className="text-sm text-slate-300 mt-2 leading-relaxed">
                                        This investigation requires human approval before the detection script can be executed in the sandbox.
                                    </p>
                                    <div className="mt-4 flex items-center space-x-4">
                                        <div className="bg-[#0F172A] rounded-lg px-3 py-2 border border-slate-700/50">
                                            <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Risk Level</p>
                                            <p className={`text-sm font-bold mt-0.5 ${task.approval_risk_level === 'critical' ? 'text-rose-400' :
                                                task.approval_risk_level === 'high' ? 'text-amber-400' : 'text-yellow-400'
                                                }`}>{(task.approval_risk_level || 'medium').toUpperCase()}</p>
                                        </div>
                                        <div className="bg-[#0F172A] rounded-lg px-3 py-2 border border-slate-700/50 flex-1">
                                            <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Reason</p>
                                            <p className="text-sm text-slate-300 mt-0.5">{task.approval_reason || 'Manual review required'}</p>
                                        </div>
                                    </div>

                                    {user?.role === 'admin' ? (
                                        <>
                                            <div className="mt-4">
                                                <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center">
                                                    <MessageSquare className="w-3.5 h-3.5 mr-1.5" /> Comment (optional)
                                                </label>
                                                <textarea
                                                    value={approvalComment}
                                                    onChange={(e) => setApprovalComment(e.target.value)}
                                                    placeholder="Add a note..."
                                                    className="mt-2 w-full bg-[#0F172A] border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 resize-none"
                                                    rows={2}
                                                />
                                            </div>

                                            <div className="mt-4 flex items-center space-x-3">
                                                <button
                                                    disabled={approvalSubmitting}
                                                    onClick={async () => {
                                                        setApprovalSubmitting(true);
                                                        try {
                                                            await decideApproval(task.pending_approval_id!, true, approvalComment);
                                                            const updated = await fetchTaskDetail(id!);
                                                            setTask(updated);
                                                            setApprovalComment('');
                                                        } catch (e) {
                                                            alert('Failed to approve');
                                                        } finally {
                                                            setApprovalSubmitting(false);
                                                        }
                                                    }}
                                                    className="flex items-center px-5 py-2.5 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20 hover:bg-emerald-500/20 transition-all text-sm font-semibold"
                                                >
                                                    <ShieldCheck className="w-4 h-4 mr-2" />
                                                    {approvalSubmitting ? 'Submitting...' : 'Approve & Execute'}
                                                </button>
                                                <button
                                                    disabled={approvalSubmitting}
                                                    onClick={async () => {
                                                        setApprovalSubmitting(true);
                                                        try {
                                                            await decideApproval(task.pending_approval_id!, false, approvalComment || 'Rejected by reviewer');
                                                            const updated = await fetchTaskDetail(id!);
                                                            setTask(updated);
                                                            setApprovalComment('');
                                                        } catch (e) {
                                                            alert('Failed to reject');
                                                        } finally {
                                                            setApprovalSubmitting(false);
                                                        }
                                                    }}
                                                    className="flex items-center px-5 py-2.5 bg-rose-500/10 text-rose-400 rounded-lg border border-rose-500/20 hover:bg-rose-500/20 transition-all text-sm font-semibold"
                                                >
                                                    <XCircle className="w-4 h-4 mr-2" />
                                                    Reject
                                                </button>
                                            </div>
                                        </>
                                    ) : (
                                        <div className="mt-4 bg-[#0F172A] p-4 rounded-lg border border-slate-700/50">
                                            <p className="text-sm font-medium text-slate-300 flex items-center">
                                                <AlertTriangle className="w-4 h-4 mr-2 text-amber-400/80" />
                                                This investigation is awaiting approval from an administrator.
                                            </p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Rejected Banner */}
                    {task.status === 'rejected' && (
                        <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-5">
                            <div className="flex items-center text-purple-400">
                                <XCircle className="w-5 h-5 mr-3" />
                                <div>
                                    <h3 className="font-bold text-sm">Investigation Rejected</h3>
                                    <p className="text-xs text-slate-400 mt-1">This investigation was rejected during the approval process and was not executed.</p>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Prompt */}
                    <div className="bg-[#1E293B] border-l-4 border-l-cyan-500 border-y border-r border-slate-700/50 rounded-r-xl p-6 shadow-sm">
                        <div className="flex items-center mb-3">
                            <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">Investigation Brief</span>
                        </div>
                        <p className="text-slate-200 leading-relaxed whitespace-pre-wrap font-medium text-[15px]">
                            {task.input?.prompt || 'No investigation brief provided'}
                        </p>
                    </div>

                    {/* Investigation Steps Indicator */}
                    {steps.length > 1 && (
                        <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6 shadow-sm">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-4">Investigation Steps</h3>
                            <div className="flex items-center justify-center space-x-2">
                                {Array.from({ length: Math.max(steps.length, task.step_count || 0) }, (_, i) => i + 1).map((stepNum) => {
                                    const step = steps.find(s => s.step_number === stepNum);
                                    const isCompleted = step?.status === 'completed';
                                    const isFailed = step?.status === 'failed';
                                    const isRunning = step?.status === 'running' || step?.status === 'pending';
                                    const stepLabel = stepNum === 1 ? 'Initial Analysis' : stepNum === 2 ? 'Enrichment' : 'Deep Analysis';
                                    return (
                                        <div key={stepNum} className="flex items-center">
                                            <button
                                                onClick={() => setExpandedSteps(prev => ({ ...prev, [stepNum]: !prev[stepNum] }))}
                                                className={`flex items-center space-x-2 px-4 py-2.5 rounded-lg border transition-all ${expandedSteps[stepNum]
                                                    ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                                                    : isCompleted
                                                        ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20'
                                                        : isFailed
                                                            ? 'bg-rose-500/10 border-rose-500/20 text-rose-400'
                                                            : 'bg-slate-700/30 border-slate-600/30 text-slate-400'
                                                    }`}
                                            >
                                                {isCompleted ? (
                                                    <CheckCircle className="w-4 h-4" />
                                                ) : isFailed ? (
                                                    <AlertTriangle className="w-4 h-4" />
                                                ) : isRunning ? (
                                                    <Loader2 className="w-4 h-4 animate-spin" />
                                                ) : (
                                                    <Circle className="w-4 h-4" />
                                                )}
                                                <span className="text-xs font-bold uppercase tracking-wider">Step {stepNum}: {stepLabel}</span>
                                            </button>
                                            {stepNum < Math.max(steps.length, task.step_count || 0) && (
                                                <ChevronRight className="w-4 h-4 text-slate-600 mx-1" />
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                            <p className="text-xs text-slate-500 text-center mt-3">
                                {steps.length} step{steps.length > 1 ? 's' : ''} completed — Click to expand
                            </p>
                        </div>
                    )}

                    {/* Expanded Step Cards */}
                    {steps.length > 1 && steps.map((step) => {
                        if (!expandedSteps[step.step_number]) return null;
                        const stepLabel = step.step_number === 1 ? 'Initial Analysis' : step.step_number === 2 ? 'Threat Intel Enrichment' : 'Deep Analysis';
                        return (
                            <div key={step.id} className="bg-[#0B1120] border border-cyan-500/20 rounded-xl overflow-hidden shadow-xl">
                                <div className="bg-[#1E293B] px-5 py-3 flex items-center justify-between border-b border-slate-700/50">
                                    <div className="flex items-center">
                                        <Zap className="w-4 h-4 text-cyan-400 mr-2.5" />
                                        <span className="text-sm font-semibold text-slate-200 tracking-wide uppercase">
                                            Step {step.step_number}: {stepLabel}
                                        </span>
                                        <span className={`ml-3 px-2 py-0.5 rounded text-xs font-bold uppercase ${step.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                                            }`}>{step.status}</span>
                                        {step.execution_mode === 'template' && (
                                            <span className="ml-2 flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" title="Executed natively using an optimized skill template">
                                                <Zap className="w-3 h-3 mr-1" /> Template
                                            </span>
                                        )}
                                        {step.execution_mode === 'generated' && (
                                            <span className="ml-2 flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/20" title="Executed using dynamic LLM-generated code">
                                                <Terminal className="w-3 h-3 mr-1" /> Generated
                                            </span>
                                        )}
                                        {step.execution_mode === 'hybrid' && (
                                            <span className="ml-2 flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase bg-blue-500/10 text-blue-400 border border-blue-500/20" title="Executed using a hybrid approach">
                                                <AlertTriangle className="w-3 h-3 mr-1" /> Hybrid
                                            </span>
                                        )}
                                    </div>
                                    <div className="flex items-center space-x-4 text-xs text-slate-500 font-mono">
                                        {step.execution_ms && <span>{(step.execution_ms / 1000).toFixed(1)}s</span>}
                                        <span>{step.tokens_used_input + step.tokens_used_output} tokens</span>
                                    </div>
                                </div>

                                {/* Step Prompt */}
                                <div className="px-5 py-4 border-b border-slate-700/30">
                                    <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Step Prompt</p>
                                    <p className="text-sm text-slate-300 leading-relaxed">{step.prompt}</p>
                                </div>

                                {/* Step Parameters (collapsible) */}
                                {step.execution_mode === 'template' && step.parameters_used && Object.keys(step.parameters_used).length > 0 && (
                                    <div className="border-b border-slate-700/30">
                                        <button
                                            onClick={() => setShowStepParams(prev => ({ ...prev, [step.step_number]: !prev[step.step_number] }))}
                                            className="px-5 py-3 flex items-center text-xs font-semibold text-slate-400 hover:text-white transition-colors w-full"
                                        >
                                            {showStepParams[step.step_number] ? <ChevronUp className="w-3.5 h-3.5 mr-2" /> : <ChevronDown className="w-3.5 h-3.5 mr-2" />}
                                            <ListFilter className="w-3.5 h-3.5 mr-2" />
                                            {showStepParams[step.step_number] ? 'Hide Sourced Parameters' : 'View Sourced Parameters'}
                                        </button>
                                        {showStepParams[step.step_number] && (
                                            <div className="bg-[#0F172A]/50 p-4 border-t border-slate-700/30">
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                    {Object.entries(step.parameters_used).map(([key, value]) => {
                                                        // Simplify rendering for complex objects
                                                        let displayValue = String(value);
                                                        if (typeof value === 'object' && value !== null) {
                                                            displayValue = 'JSON Context Omitted for Readability';
                                                        }
                                                        if (key === 'log_data' && typeof value === 'string' && value.length > 100) {
                                                            displayValue = value.substring(0, 100) + '... (truncated)';
                                                        }

                                                        return (
                                                            <div key={key} className="bg-[#1E293B] border border-slate-700/50 rounded-lg p-3">
                                                                <p className="text-[10px] text-cyan-400/80 font-mono mb-1">{key}</p>
                                                                <p className="text-sm text-slate-200 font-medium truncate" title={displayValue}>{displayValue}</p>
                                                            </div>
                                                        );
                                                    })}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}

                                {/* Step Code (collapsible) */}
                                {step.generated_code && (
                                    <div className="border-b border-slate-700/30">
                                        <button
                                            onClick={() => setShowStepCode(prev => ({ ...prev, [step.step_number]: !prev[step.step_number] }))}
                                            className="px-5 py-3 flex items-center text-xs font-semibold text-slate-400 hover:text-white transition-colors w-full"
                                        >
                                            {showStepCode[step.step_number] ? <ChevronUp className="w-3.5 h-3.5 mr-2" /> : <ChevronDown className="w-3.5 h-3.5 mr-2" />}
                                            <FileCode2 className="w-3.5 h-3.5 mr-2" />
                                            {showStepCode[step.step_number] ? 'Hide Code' : 'View Code'}
                                        </button>
                                        {showStepCode[step.step_number] && (
                                            <SyntaxHighlighter
                                                language="python"
                                                style={atomDark}
                                                customStyle={{ margin: 0, padding: '1rem', background: 'transparent', fontSize: '0.85rem' }}
                                                showLineNumbers
                                            >
                                                {step.generated_code}
                                            </SyntaxHighlighter>
                                        )}
                                    </div>
                                )}

                                {/* Step Analysis Report */}
                                {step.output && (() => {
                                    try {
                                        const parsed = JSON.parse(step.output);
                                        const findingsKey = Object.keys(parsed).find(k => ['findings', 'vulnerabilities', 'suspicious_files', 'iocs_found', 'matches'].includes(k));
                                        const findings = findingsKey ? parsed[findingsKey] : null;
                                        const statsKey = Object.keys(parsed).find(k => ['statistics', 'risk_summary', 'scan_coverage', 'risk_score'].includes(k));
                                        const stats = statsKey && typeof parsed[statsKey] === 'object' ? parsed[statsKey] : (parsed['risk_score'] !== undefined ? { risk_score: parsed['risk_score'] } : null);
                                        const recsKey = Object.keys(parsed).find(k => ['recommendations', 'recommended_actions', 'containment_actions'].includes(k));
                                        const recommendations = recsKey ? parsed[recsKey] : null;

                                        return (
                                            <div className="divide-y divide-slate-700/50">
                                                {stats && Object.keys(stats).length > 0 && (
                                                    <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#0F172A]/50">
                                                        {Object.entries(stats).map(([k, v], i) => (
                                                            <div key={i} className="bg-[#1E293B] rounded-lg p-3 border border-slate-700/50">
                                                                <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-1">{k.replace(/_/g, ' ')}</p>
                                                                <p className="text-lg font-mono text-white font-bold">{String(v)}</p>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                                {findings && Array.isArray(findings) && findings.length > 0 && (
                                                    <div className="p-4">
                                                        <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-3 flex items-center">
                                                            <Target className="w-3.5 h-3.5 mr-2" /> Findings
                                                        </h4>
                                                        <div className="space-y-2">
                                                            {findings.slice(0, 5).map((f: any, i: number) => (
                                                                <div key={i} className="bg-[#1E293B] border border-slate-700/50 rounded-lg p-3 flex items-start text-sm">
                                                                    {(f.severity?.toLowerCase() === 'critical' || f.severity?.toLowerCase() === 'high') ? (
                                                                        <AlertTriangle className="w-4 h-4 text-rose-400 mt-0.5 mr-2.5 shrink-0" />
                                                                    ) : (
                                                                        <Info className="w-4 h-4 text-blue-400 mt-0.5 mr-2.5 shrink-0" />
                                                                    )}
                                                                    <div className="flex-1">
                                                                        <h5 className="font-semibold text-slate-200 text-sm">{f.title || f.name || `Finding #${i + 1}`}</h5>
                                                                        <p className="text-xs text-slate-400 mt-1 font-mono line-clamp-2">{f.description || f.details || JSON.stringify(f)}</p>
                                                                    </div>
                                                                </div>
                                                            ))}
                                                            {findings.length > 5 && <p className="text-xs text-slate-500 text-center">+ {findings.length - 5} more findings</p>}
                                                        </div>
                                                    </div>
                                                )}
                                                {recommendations && Array.isArray(recommendations) && recommendations.length > 0 && (
                                                    <div className="p-4">
                                                        <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-3 flex items-center">
                                                            <ListChecks className="w-3.5 h-3.5 mr-2" /> Recommendations
                                                        </h4>
                                                        <div className="space-y-2">
                                                            {recommendations.map((rec: string, i: number) => (
                                                                <div key={i} className="flex items-start text-xs text-slate-300">
                                                                    <CheckSquare className="w-3.5 h-3.5 text-cyan-500 mr-2 mt-0.5 shrink-0" />
                                                                    <span className="leading-relaxed">{rec}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                                <div className="p-4 bg-[#0F172A]/50">
                                                    <button
                                                        onClick={() => setShowStepRawJson(prev => ({ ...prev, [step.step_number]: !prev[step.step_number] }))}
                                                        className="flex items-center text-xs font-semibold text-slate-400 hover:text-white transition-colors"
                                                    >
                                                        {showStepRawJson[step.step_number] ? <ChevronUp className="w-3.5 h-3.5 mr-2" /> : <ChevronDown className="w-3.5 h-3.5 mr-2" />}
                                                        {showStepRawJson[step.step_number] ? 'Hide Raw JSON' : 'View Raw JSON'}
                                                    </button>
                                                    {showStepRawJson[step.step_number] && (
                                                        <div className="mt-3 bg-black rounded-lg p-3 overflow-x-auto border border-slate-700/50">
                                                            <pre className="text-cyan-400/90 font-mono text-[12px] leading-relaxed">
                                                                {JSON.stringify(parsed, null, 2)}
                                                            </pre>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        );
                                    } catch {
                                        return (
                                            <div className="p-4 bg-black overflow-x-auto">
                                                <pre className="text-cyan-400/90 font-mono text-[12px] leading-relaxed whitespace-pre-wrap">{step.output}</pre>
                                            </div>
                                        );
                                    }
                                })()}
                            </div>
                        );
                    })}

                    {!isFinished && (
                        <div className="flex flex-col items-center justify-center p-12 bg-[#0F172A] border border-slate-700/50 border-dashed rounded-xl">
                            <Loader2 className="w-10 h-10 text-cyan-500 animate-spin mb-4" />
                            <p className="text-white font-medium text-lg tracking-tight">Zovark is analyzing your investigation...</p>
                            <p className="text-slate-400 text-sm mt-2">Running detection scripts, validating findings, and executing in sandbox.</p>
                        </div>
                    )}

                    {/* Plain-English Summary */}
                    {(task?.output as any)?.plain_english_summary && (
                      <div className="mb-6">
                        <h3 className="text-[11px] uppercase tracking-[0.15em] mb-3"
                            style={{color: '#94A3B8', fontFamily: "'JetBrains Mono', monospace"}}>
                          INVESTIGATION SUMMARY
                        </h3>
                        <div className="rounded-lg p-4"
                             style={{borderColor: '#1B2432', border: '1px solid #1B2432', background: '#0D1117'}}>
                          {((task.output as any).plain_english_summary as string).split('\n').map((line: string, i: number) => (
                            <p key={i} className="text-sm mb-1" style={{color: '#E2E8F0', fontFamily: "'JetBrains Mono', monospace"}}>
                              {line}
                            </p>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Detection Script */}
                    {task.output?.code && (
                        <div className="bg-[#0B1120] border border-slate-700/50 rounded-xl overflow-hidden shadow-xl">
                            <div className="bg-[#1E293B] px-5 py-3 flex items-center justify-between border-b border-slate-700/50">
                                <div className="flex items-center">
                                    <FileCode2 className="w-4 h-4 text-cyan-400 mr-2.5" />
                                    <span className="text-sm font-semibold text-slate-200 tracking-wide uppercase">Detection Script</span>
                                </div>
                                <button
                                    onClick={handleCopy}
                                    className="flex items-center text-xs font-semibold text-slate-400 hover:text-white transition-colors bg-[#0B1120] px-3 py-1.5 rounded-md border border-slate-700/50"
                                >
                                    {copied ? <Check className="w-3.5 h-3.5 mr-1.5 text-cyan-500" /> : <Copy className="w-3.5 h-3.5 mr-1.5" />}
                                    {copied ? 'Copied' : 'Copy'}
                                </button>
                            </div>
                            <SyntaxHighlighter
                                language="python"
                                style={atomDark}
                                customStyle={{ margin: 0, padding: '1.5rem', background: 'transparent', fontSize: '0.9rem' }}
                                showLineNumbers
                            >
                                {task.output.code}
                            </SyntaxHighlighter>
                        </div>
                    )}

                    {/* Analysis Report */}
                    {task.output?.stdout && (
                        <div className="bg-[#0B1120] border border-slate-700/50 rounded-xl overflow-hidden shadow-xl">
                            <div className="bg-[#1E293B] px-5 py-3 flex items-center border-b border-slate-700/50">
                                <Terminal className="w-4 h-4 text-cyan-400 mr-2.5" />
                                <span className="text-sm font-semibold text-slate-200 tracking-wide uppercase">Analysis Report</span>
                            </div>
                            <div className="p-0">
                                {(() => {
                                    try {
                                        const parsed = JSON.parse(task.output.stdout);
                                        // It's valid JSON. Render structured cards.

                                        // Find likely arrays of findings
                                        const findingsKey = Object.keys(parsed).find(k => ['findings', 'vulnerabilities', 'suspicious_files', 'iocs_found', 'matches'].includes(k));
                                        const findings = findingsKey ? parsed[findingsKey] : null;

                                        // Find statistics
                                        const statsKey = Object.keys(parsed).find(k => ['statistics', 'risk_summary', 'scan_coverage', 'risk_score'].includes(k));
                                        const stats = statsKey && typeof parsed[statsKey] === 'object' ? parsed[statsKey] : (parsed['risk_score'] !== undefined ? { risk_score: parsed['risk_score'] } : null);

                                        // Find recommendations
                                        const recsKey = Object.keys(parsed).find(k => ['recommendations', 'recommended_actions', 'containment_actions'].includes(k));
                                        const recommendations = recsKey ? parsed[recsKey] : null;

                                        return (
                                            <div className="divide-y divide-slate-700/50">
                                                {/* Stats Row */}
                                                {stats && Object.keys(stats).length > 0 && (
                                                    <div className="p-6 grid grid-cols-2 sm:grid-cols-4 gap-4 bg-[#0F172A]/50">
                                                        {Object.entries(stats).map(([k, v], i) => (
                                                            <div key={i} className="bg-[#1E293B] rounded-lg p-4 border border-slate-700/50">
                                                                <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">
                                                                    {k.replace(/_/g, ' ')}
                                                                </p>
                                                                <p className="text-xl font-mono text-white font-bold">{String(v)}</p>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}

                                                {/* Findings */}
                                                {findings && Array.isArray(findings) && findings.length > 0 && (
                                                    <div className="p-6">
                                                        <h4 className="text-sm font-bold text-cyan-400 uppercase tracking-wider mb-4 flex items-center">
                                                            <Target className="w-4 h-4 mr-2" /> Key Findings
                                                        </h4>
                                                        <div className="space-y-4">
                                                            {findings.map((f: any, i: number) => {
                                                                const isHighSeverity = f.severity?.toLowerCase() === 'critical' || f.severity?.toLowerCase() === 'high';
                                                                const title = f.title || f.name || f.issue || f.finding || `Finding #${i + 1}`;
                                                                const desc = f.description || f.details || JSON.stringify(f);
                                                                return (
                                                                    <div key={i} className="bg-[#1E293B] border border-slate-700/50 rounded-lg p-4 flex items-start">
                                                                        {isHighSeverity ? (
                                                                            <AlertTriangle className="w-5 h-5 text-rose-400 mt-0.5 mr-3 shrink-0" />
                                                                        ) : (
                                                                            <Info className="w-5 h-5 text-blue-400 mt-0.5 mr-3 shrink-0" />
                                                                        )}
                                                                        <div className="flex-1">
                                                                            <div className="flex items-center justify-between mb-1">
                                                                                <h5 className="font-semibold text-slate-200">{title}</h5>
                                                                                {f.severity && <SeverityBadge severity={f.severity} />}
                                                                            </div>
                                                                            <p className="text-sm text-slate-400 leading-relaxed font-mono whitespace-pre-wrap">{desc}</p>
                                                                        </div>
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Recommendations */}
                                                {recommendations && Array.isArray(recommendations) && recommendations.length > 0 && (
                                                    <div className="p-6">
                                                        <h4 className="text-sm font-bold text-cyan-400 uppercase tracking-wider mb-4 flex items-center">
                                                            <ListChecks className="w-4 h-4 mr-2" /> Recommendations
                                                        </h4>
                                                        <div className="space-y-3">
                                                            {recommendations.map((rec: string, i: number) => (
                                                                <div key={i} className="flex items-start text-sm text-slate-300">
                                                                    <CheckSquare className="w-4 h-4 text-cyan-500 mr-3 mt-0.5 shrink-0" />
                                                                    <span className="leading-relaxed">{rec}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Raw JSON Toggle */}
                                                <div className="p-6 bg-[#0F172A]/50">
                                                    <button
                                                        onClick={() => setShowRawJson(!showRawJson)}
                                                        className="flex items-center text-sm font-semibold text-slate-400 hover:text-white transition-colors"
                                                    >
                                                        {showRawJson ? <ChevronUp className="w-4 h-4 mr-2" /> : <ChevronDown className="w-4 h-4 mr-2" />}
                                                        {showRawJson ? 'Hide Raw JSON' : 'View Raw JSON'}
                                                    </button>
                                                    {showRawJson && (
                                                        <div className="mt-4 bg-black rounded-lg p-4 overflow-x-auto border border-slate-700/50">
                                                            <pre className="text-cyan-400/90 font-mono text-[13px] leading-relaxed">
                                                                {JSON.stringify(parsed, null, 2)}
                                                            </pre>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        );
                                    } catch (e) {
                                        // Fallback for non-JSON or parsing error
                                        return (
                                            <div className="p-6 bg-black overflow-x-auto">
                                                <pre className="text-cyan-400/90 font-mono text-[13px] leading-relaxed whitespace-pre-wrap">
                                                    {task.output?.stdout}
                                                </pre>
                                            </div>
                                        );
                                    }
                                })()}
                            </div>
                        </div>
                    )}

                    {/* MITRE ATT&CK Techniques */}
                    {isFinished && (() => {
                        let outputMitre: MitreTechnique[] | undefined;
                        try {
                            if (task.output?.stdout) {
                                const parsed = JSON.parse(task.output.stdout);
                                if (parsed.mitre_attack && Array.isArray(parsed.mitre_attack)) {
                                    outputMitre = parsed.mitre_attack;
                                }
                            }
                        } catch { /* ignore parse errors */ }

                        const techniques = getMitreTechniques(task.task_type, outputMitre);
                        if (techniques.length === 0) return null;

                        return (
                            <div className="bg-[#0B1120] border border-slate-700/50 rounded-xl overflow-hidden shadow-xl">
                                <div className="bg-[#1E293B] px-5 py-3 flex items-center border-b border-slate-700/50">
                                    <Crosshair className="w-4 h-4 text-rose-400 mr-2.5" />
                                    <span className="text-sm font-semibold text-slate-200 tracking-wide uppercase">MITRE ATT&CK Techniques</span>
                                    <span className="ml-2 text-xs text-slate-500 font-mono">({techniques.length})</span>
                                </div>
                                <div className="p-5">
                                    <div className="flex flex-wrap gap-2">
                                        {techniques.map((t, idx) => (
                                            <a
                                                key={idx}
                                                href={getMitreAttackUrl(t.id)}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="group inline-flex items-center bg-[#1a1a1e] border border-zinc-700 rounded-lg px-3 py-2 hover:border-blue-500/50 hover:bg-blue-500/5 transition-all cursor-pointer"
                                            >
                                                <span className="font-mono text-sm font-bold text-blue-400 group-hover:text-blue-300 mr-2">{t.id}</span>
                                                <span className="text-sm text-slate-200 mr-2">{t.name}</span>
                                                <span className="text-[10px] text-slate-500 font-medium uppercase tracking-wider">{t.tactic}</span>
                                            </a>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        );
                    })()}

                    {/* IOCs with Confidence */}
                    {isFinished && (() => {
                        try {
                            if (!task.output?.stdout) return null;
                            const parsed = JSON.parse(task.output.stdout);
                            const iocs = parsed.iocs || parsed.iocs_found || parsed.indicators || [];
                            if (!Array.isArray(iocs) || iocs.length === 0) return null;

                            return (
                                <div className="bg-[#0B1120] border border-slate-700/50 rounded-xl overflow-hidden shadow-xl">
                                    <div className="bg-[#1E293B] px-5 py-3 flex items-center border-b border-slate-700/50">
                                        <ShieldAlert className="w-4 h-4 text-amber-400 mr-2.5" />
                                        <span className="text-sm font-semibold text-slate-200 tracking-wide uppercase">Indicators of Compromise</span>
                                        <span className="ml-2 text-xs text-slate-500 font-mono">({iocs.length})</span>
                                    </div>
                                    <div className="p-5">
                                        <div className="space-y-2">
                                            {iocs.map((ioc: any, idx: number) => {
                                                const value = typeof ioc === 'string' ? ioc : (ioc.value || ioc.indicator || ioc.ioc || JSON.stringify(ioc));
                                                const iocType = typeof ioc === 'object' ? (ioc.type || ioc.ioc_type || '') : '';
                                                const confidence = typeof ioc === 'object' ? ioc.confidence : undefined;

                                                return (
                                                    <div key={idx} className="flex items-center justify-between bg-[#1a1a1e] border border-zinc-700 rounded-lg px-3 py-2">
                                                        <div className="flex items-center space-x-2 min-w-0">
                                                            {iocType && (
                                                                <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider shrink-0">{iocType}</span>
                                                            )}
                                                            <span className="text-sm font-mono text-slate-200 truncate">{value}</span>
                                                        </div>
                                                        <IOCConfidenceBadge confidence={confidence} />
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                </div>
                            );
                        } catch { return null; }
                    })()}

                    {/* MITRE ATT&CK Timeline */}
                    {steps.length > 0 && (
                        <MitreTimeline steps={steps} taskType={task.task_type} />
                    )}
                </div>

                {/* Right Column (40%) */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Metrics Card */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6 shadow-sm">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-5 pb-3 border-b border-slate-700/50">Performance Metrics</h3>

                        <div className="space-y-5">
                            <div className="flex items-start">
                                <Cpu className="w-5 h-5 text-cyan-400 mr-3.5 mt-0.5 opacity-80" />
                                <div>
                                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">AI Compute</p>
                                    <p className="text-sm font-bold text-white font-mono mt-1">
                                        {task.tokens_used_input || 0} In / {task.tokens_used_output || 0} Out
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-start">
                                <Clock3 className="w-5 h-5 text-amber-400 mr-3.5 mt-0.5 opacity-80" />
                                <div>
                                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Analysis Duration</p>
                                    <p className="text-sm font-bold text-white font-mono mt-1">
                                        {task.execution_ms ? `${(task.execution_ms / 1000).toFixed(2)}s` : 'Counting...'}
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-start pt-5 border-t border-slate-700/50 mt-5">
                                <DollarSign className="w-5 h-5 text-cyan-400 mr-3.5 mt-0.5 opacity-80" />
                                <div>
                                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Est. Compute Cost</p>
                                    <p className="text-sm font-bold text-white font-mono mt-1">
                                        ${totalCost.toFixed(6)}
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* MITRE ATT&CK */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6 shadow-sm">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-5 pb-3 border-b border-slate-700/50 flex items-center">
                            <Crosshair className="w-4 h-4 mr-2 text-rose-400" /> MITRE ATT&CK Mapping
                        </h3>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between bg-[#0F172A] rounded-lg p-3 border border-slate-700/30">
                                <div>
                                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Tactic</p>
                                    <p className="text-sm font-bold text-slate-200 mt-0.5">{getMitreMapping(task.task_type).tactic}</p>
                                </div>
                                <span className="px-2 py-0.5 bg-rose-500/10 text-rose-400 text-xs font-mono rounded border border-rose-500/20">{getMitreMapping(task.task_type).tacticId}</span>
                            </div>
                            <div className="flex items-center justify-between bg-[#0F172A] rounded-lg p-3 border border-slate-700/30">
                                <div>
                                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Technique</p>
                                    <p className="text-sm font-bold text-slate-200 mt-0.5">{getMitreMapping(task.task_type).technique}</p>
                                </div>
                                <span className="px-2 py-0.5 bg-amber-500/10 text-amber-400 text-xs font-mono rounded border border-amber-500/20">{getMitreMapping(task.task_type).techniqueId}</span>
                            </div>
                        </div>
                    </div>

                    {/* Sandbox Isolation */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6 shadow-sm">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-5 pb-3 border-b border-slate-700/50 flex items-center">
                            <ShieldAlert className="w-4 h-4 mr-2 text-cyan-400" /> Sandbox Isolation
                        </h3>
                        <ul className="space-y-4">
                            <li className="flex items-start text-sm font-medium text-slate-300 group">
                                <CheckCircle className="w-4 h-4 text-cyan-500 mr-3 mt-0.5 shrink-0" />
                                <div>
                                    <span className="text-white block mb-0.5">Network Isolation</span>
                                    <span className="text-xs text-slate-500 font-mono">--network=none applied</span>
                                </div>
                            </li>
                            <li className="flex items-start text-sm font-medium text-slate-300 group">
                                <CheckCircle className="w-4 h-4 text-cyan-500 mr-3 mt-0.5 shrink-0" />
                                <div>
                                    <span className="text-white block mb-0.5">Syscall Restriction</span>
                                    <span className="text-xs text-slate-500 font-mono">Strict seccomp profile</span>
                                </div>
                            </li>
                            <li className="flex items-start text-sm font-medium text-slate-300 group">
                                <CheckCircle className="w-4 h-4 text-cyan-500 mr-3 mt-0.5 shrink-0" />
                                <div>
                                    <span className="text-white block mb-0.5">Resource Limits</span>
                                    <span className="text-xs text-slate-500 font-mono">0.5 CPU, 256MB RAM</span>
                                </div>
                            </li>
                            <li className="flex items-start text-sm font-medium text-slate-300 group">
                                <CheckCircle className="w-4 h-4 text-cyan-500 mr-3 mt-0.5 shrink-0" />
                                <div>
                                    <span className="text-white block mb-0.5">Execution Timeout</span>
                                    <span className="text-xs text-slate-500 font-mono">30s auto-kill timer active</span>
                                </div>
                            </li>
                            <li className="flex items-start text-sm font-medium text-slate-300 group">
                                <CheckCircle className="w-4 h-4 text-cyan-500 mr-3 mt-0.5 shrink-0" />
                                <div>
                                    <span className="text-white block mb-0.5">Code Validation</span>
                                    <span className="text-xs text-slate-500 font-mono">AST pre-filter passed</span>
                                </div>
                            </li>
                        </ul>
                    </div>

                    {/* Investigation Timeline */}
                    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-6 shadow-sm">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-6 pb-3 border-b border-slate-700/50 flex items-center">
                            <ListFilter className="w-4 h-4 mr-2" /> Investigation Timeline
                        </h3>
                        {timeline.length > 0 ? (
                            <div className="space-y-0 pl-1">
                                {timeline.map((entry, idx) => {
                                    let Icon = Circle;
                                    let iconColor = "text-slate-400";
                                    let bgRing = "bg-slate-800 ring-[#1E293B]";

                                    if (entry.icon === 'created') {
                                        Icon = Target;
                                        iconColor = "text-cyan-400";
                                        bgRing = "bg-cyan-900 ring-[#1E293B]";
                                    } else if (entry.icon === 'play') {
                                        Icon = Zap;
                                        iconColor = "text-amber-400";
                                        bgRing = "bg-amber-900 ring-[#1E293B]";
                                    } else if (entry.icon === 'check') {
                                        Icon = CheckCircle;
                                        iconColor = "text-emerald-400";
                                        bgRing = "bg-emerald-900 ring-[#1E293B]";
                                    } else if (entry.icon === 'alert') {
                                        Icon = ShieldAlert;
                                        iconColor = "text-rose-400";
                                        bgRing = "bg-rose-900 ring-[#1E293B]";
                                    } else if (entry.icon === 'tool') {
                                        Icon = Terminal;
                                        iconColor = "text-purple-400";
                                        bgRing = "bg-purple-900 ring-[#1E293B]";
                                    }

                                    return (
                                        <div key={entry.id} className="flex relative pb-6 group">
                                            <div className="flex flex-col items-center mr-4">
                                                <div className={`w-8 h-8 rounded-full flex items-center justify-center ring-4 shadow-sm z-10 ${bgRing}`}>
                                                    <Icon className={`w-4 h-4 ${iconColor}`} />
                                                </div>
                                                {idx !== timeline.length - 1 && (
                                                    <div className="w-px h-full bg-slate-700/50 absolute top-8" />
                                                )}
                                            </div>
                                            <div className="pb-1 mt-1 flex-1 group-hover:translate-x-1 transition-transform">
                                                <div className="flex justify-between items-start">
                                                    <p className="text-sm font-semibold text-slate-200">
                                                        {entry.description}
                                                    </p>
                                                    <p className="text-xs font-mono text-slate-500 whitespace-nowrap ml-4 mt-0.5">
                                                        {new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                                    </p>
                                                </div>
                                                {entry.duration_ms !== undefined && (
                                                    <p className="text-xs text-slate-500 mt-1 flex items-center">
                                                        <Clock3 className="w-3 h-3 mr-1" />
                                                        Took {entry.duration_ms / 1000}s
                                                    </p>
                                                )}
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        ) : (
                            <div className="text-slate-500 text-sm font-medium text-center py-4 text-center">No timeline events yet.</div>
                        )}
                    </div>
                </div>
            </div>
        </div >
    );
};

export default TaskDetail;
