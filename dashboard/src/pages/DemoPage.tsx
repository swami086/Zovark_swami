import { useState, useEffect } from 'react';
import { useDemo } from '../hooks/useDemo';
import InvestigationWaterfall from '../components/InvestigationWaterfall';
import StepDetailPanel from '../components/StepDetailPanel';
import DemoBanner from '../components/DemoBanner';
import ExecutiveSummary from '../components/ExecutiveSummary';
import PipelineVisualization from '../components/PipelineVisualization';
import TerminalBlock from '../components/TerminalBlock';
import MetricCard from '../components/MetricCard';
import StatusBadge from '../components/StatusBadge';
import RiskBar from '../components/RiskBar';
import { C2_BEACON_INVESTIGATION } from '../demo/c2BeaconScenario';
import type { WorkflowStep } from '../types';
import { Shield, Clock3, Target, Zap, AlertTriangle, ChevronRight, Play, RotateCcw } from 'lucide-react';

type DemoStep = 1 | 2 | 3 | 4;

interface Scenario {
  id: string;
  name: string;
  mitre: string;
  description: string;
  accentColor: string;
  borderColor: string;
}

const SCENARIOS: Scenario[] = [
  {
    id: 'brute_force',
    name: 'Brute Force',
    mitre: 'T1110',
    description: '500 failed SSH logins from external IP',
    accentColor: '#FF4444',
    borderColor: '#FF4444',
  },
  {
    id: 'phishing',
    name: 'Phishing',
    mitre: 'T1566',
    description: 'Credential harvesting via typosquatting domain',
    accentColor: '#FFAA00',
    borderColor: '#FFAA00',
  },
  {
    id: 'kerberoasting',
    name: 'Kerberoasting',
    mitre: 'T1558.003',
    description: 'RC4 downgrade attack on service tickets',
    accentColor: '#00FF88',
    borderColor: '#00FF88',
  },
];

const TERMINAL_LINES_BY_STAGE: Record<string, { text: string; color?: string }[]> = {
  idle: [
    { text: '$ zovark --mode investigate --wait', color: 'var(--text-muted)' },
    { text: '[READY] Awaiting scenario selection...', color: 'var(--text-muted)' },
  ],
  ingest: [
    { text: '$ zovark investigate --scenario c2_beacon', color: 'var(--accent-green)' },
    { text: '[INGEST] Receiving SIEM alert...', color: 'var(--text-secondary)' },
    { text: '[INGEST] Dedup check: no prior investigation found', color: 'var(--text-secondary)' },
    { text: '[INGEST] PII mask applied: 0 fields redacted', color: 'var(--text-secondary)' },
    { text: '[INGEST] Skill match: c2-communication-hunt (confidence: 0.94)', color: 'var(--accent-green)' },
    { text: '[INGEST] Attack indicator detected: dns_beacon pattern', color: 'var(--accent-amber)' },
  ],
  analyze: [
    { text: '[ANALYZE] Path B selected: template + LLM param fill', color: 'var(--accent-cyan)' },
    { text: '[ANALYZE] Loading c2-communication-hunt template...', color: 'var(--text-secondary)' },
    { text: '[ANALYZE] LLM request: extracting investigation parameters', color: 'var(--accent-cyan)' },
    { text: '[ANALYZE] LLM tokens: 1,247 in / 892 out (qwen2.5:14b)', color: 'var(--text-secondary)' },
    { text: '[ANALYZE] Code generated: 87 lines, 6 checks', color: 'var(--accent-green)' },
  ],
  execute: [
    { text: '[EXECUTE] AST prefilter: PASS (no blocked imports)', color: 'var(--accent-green)' },
    { text: '[EXECUTE] Sandbox: network=none, 512MB, seccomp, 64 PIDs', color: 'var(--text-secondary)' },
    { text: '[EXECUTE] Running investigation code...', color: 'var(--text-secondary)' },
    { text: '[EXECUTE] VT: 14/72 vendors flagged updateservice-cdn.net', color: 'var(--accent-red)' },
    { text: '[EXECUTE] WHOIS: registered 3 days ago (2026-03-06)', color: 'var(--accent-amber)' },
    { text: '[EXECUTE] Exit code: 0 (1.1s)', color: 'var(--accent-green)' },
  ],
  assess: [
    { text: '[ASSESS] LLM verdict derivation...', color: 'var(--accent-cyan)' },
    { text: '[ASSESS] IOCs extracted: 5 (3 IPs, 1 domain, 1 process)', color: 'var(--text-secondary)' },
    { text: '[ASSESS] Evidence refs: 5/5 IOCs have source citations', color: 'var(--accent-green)' },
    { text: '[ASSESS] MITRE mapping: T1071.004 (DNS C2)', color: 'var(--text-secondary)' },
    { text: '[ASSESS] Signal boost: +45 (c2_beacon pattern match)', color: 'var(--accent-amber)' },
    { text: '[ASSESS] Risk score: 92 | Verdict: TRUE_POSITIVE', color: 'var(--accent-red)' },
  ],
  store: [
    { text: '[STORE] Writing agent_tasks: demo-c2-001', color: 'var(--text-secondary)' },
    { text: '[STORE] Writing investigations: 5 IOCs persisted', color: 'var(--text-secondary)' },
    { text: '[STORE] Audit event logged (synchronous_commit=on)', color: 'var(--accent-green)' },
    { text: '[STORE] Playbook triggered: isolate_and_block', color: 'var(--accent-amber)' },
    { text: '[STORE] Investigation complete. Total: 8.7s', color: 'var(--accent-green)' },
  ],
};

function getStageFromSteps(steps: WorkflowStep[]): string {
  if (steps.length === 0) return 'idle';
  const runningStep = steps.find(s => s.status === 'running');
  if (runningStep) {
    const name = runningStep.name;
    if (name === 'parse_alert') return 'ingest';
    if (name === 'generate_python') return 'analyze';
    if (name === 'execute_sandbox') return 'execute';
    if (name === 'extract_entities' || name === 'guardrail_check' || name === 'generate_report') return 'assess';
    if (name === 'complete') return 'store';
  }
  const completedNames = steps.filter(s => s.status === 'completed').map(s => s.name);
  if (completedNames.includes('complete')) return 'store';
  if (completedNames.includes('generate_report')) return 'store';
  if (completedNames.includes('guardrail_check')) return 'assess';
  if (completedNames.includes('execute_sandbox')) return 'assess';
  if (completedNames.includes('generate_python')) return 'execute';
  if (completedNames.includes('parse_alert')) return 'analyze';
  return 'ingest';
}

function getPipelineStages(stage: string): Record<string, 'queued' | 'active' | 'completed' | 'failed'> {
  const stages = ['INGEST', 'ANALYZE', 'EXECUTE', 'ASSESS', 'STORE'];
  const stageMap: Record<string, number> = { idle: -1, ingest: 0, analyze: 1, execute: 2, assess: 3, store: 4 };
  const currentIdx = stageMap[stage] ?? -1;
  const result: Record<string, 'queued' | 'active' | 'completed' | 'failed'> = {};
  stages.forEach((s, i) => {
    if (i < currentIdx) result[s] = 'completed';
    else if (i === currentIdx) result[s] = 'active';
    else result[s] = 'queued';
  });
  return result;
}

export default function DemoPage() {
  const { steps, isRunning, isComplete, startDemo } = useDemo();
  const [selectedStep, setSelectedStep] = useState<WorkflowStep | null>(null);
  const [demoStep, setDemoStep] = useState<DemoStep>(1);
  const [selectedScenario, setSelectedScenario] = useState<Scenario | null>(null);
  const [terminalLines, setTerminalLines] = useState(TERMINAL_LINES_BY_STAGE.idle);

  // Track pipeline stage from demo steps
  const currentStage = getStageFromSteps(steps);
  const pipelineStages = getPipelineStages(currentStage);

  // Update terminal lines as pipeline progresses
  useEffect(() => {
    if (demoStep === 2 && isRunning) {
      const allLines: { text: string; color?: string }[] = [];
      const stageOrder = ['ingest', 'analyze', 'execute', 'assess', 'store'];
      const currentIdx = stageOrder.indexOf(currentStage);
      for (let i = 0; i <= currentIdx; i++) {
        const stageLines = TERMINAL_LINES_BY_STAGE[stageOrder[i]];
        if (stageLines) allLines.push(...stageLines);
      }
      setTerminalLines(allLines.length > 0 ? allLines : TERMINAL_LINES_BY_STAGE.ingest);
    }
  }, [currentStage, demoStep, isRunning]);

  // Move to verdict step when complete
  useEffect(() => {
    if (isComplete && demoStep === 2) {
      // Gather all terminal lines
      const allLines: { text: string; color?: string }[] = [];
      const stageOrder = ['ingest', 'analyze', 'execute', 'assess', 'store'];
      for (const s of stageOrder) {
        const stageLines = TERMINAL_LINES_BY_STAGE[s];
        if (stageLines) allLines.push(...stageLines);
      }
      setTerminalLines(allLines);
      setTimeout(() => setDemoStep(3), 800);
    }
  }, [isComplete, demoStep]);

  const handleSelectScenario = (scenario: Scenario) => {
    setSelectedScenario(scenario);
  };

  const handleStartInvestigation = () => {
    setDemoStep(2);
    setSelectedStep(null);
    startDemo();
  };

  const handleRestart = () => {
    setDemoStep(1);
    setSelectedScenario(null);
    setTerminalLines(TERMINAL_LINES_BY_STAGE.idle);
    setSelectedStep(null);
  };

  const inv = C2_BEACON_INVESTIGATION;
  const completedSteps = steps.filter(s => s.status === 'completed').length;
  const totalDuration = steps
    .filter(s => s.status === 'completed')
    .reduce((sum, s) => sum + (s.duration_ms || 0), 0);

  return (
    <div className="space-y-4">
      <DemoBanner />

      {/* Step Indicator */}
      <div className="flex items-center gap-2 px-1">
        {[1, 2, 3, 4].map((step) => (
          <div key={step} className="flex items-center gap-2">
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-bold font-mono border transition-all ${
              demoStep === step
                ? 'border-[#00FF88] text-[#00FF88] shadow-[0_0_12px_rgba(0,255,136,0.25)]'
                : demoStep > step
                  ? 'border-[#00FF88]/40 text-[#00FF88]/60 bg-[#00FF88]/5'
                  : 'border-[#1B2432] text-[#475569]'
            }`}>
              {step}
            </div>
            <span className={`text-[11px] font-mono font-bold uppercase tracking-wider ${
              demoStep === step ? 'text-[#00FF88]' : demoStep > step ? 'text-[#00FF88]/40' : 'text-[#475569]'
            }`}>
              {step === 1 ? 'SELECT' : step === 2 ? 'PIPELINE' : step === 3 ? 'VERDICT' : 'PROMOTE'}
            </span>
            {step < 4 && <ChevronRight className="w-3 h-3 text-[#1B2432]" />}
          </div>
        ))}
      </div>

      {/* STEP 1: SELECT SCENARIO */}
      {demoStep === 1 && (
        <div className="space-y-4">
          <div>
            <h1 className="text-xl font-bold text-[#E2E8F0] font-mono">SELECT SCENARIO</h1>
            <p className="text-[#475569] text-xs mt-1 font-mono uppercase tracking-wider">
              Choose an attack scenario for the CISO demonstration
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {SCENARIOS.map((scenario) => (
              <button
                key={scenario.id}
                onClick={() => handleSelectScenario(scenario)}
                className={`flex flex-col p-5 bg-[#0D1117] rounded-lg transition-all text-left group ${
                  selectedScenario?.id === scenario.id
                    ? 'ring-1'
                    : 'border border-[#1B2432] hover:border-opacity-60'
                }`}
                style={{
                  borderColor: selectedScenario?.id === scenario.id ? scenario.borderColor : undefined,
                  boxShadow: selectedScenario?.id === scenario.id
                    ? `0 0 12px ${scenario.accentColor}25`
                    : undefined,
                  ...(selectedScenario?.id !== scenario.id ? { borderWidth: '1px', borderStyle: 'solid' } : {}),
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-bold font-mono text-[#E2E8F0]" style={{
                    color: selectedScenario?.id === scenario.id ? scenario.accentColor : undefined
                  }}>
                    {scenario.name}
                  </h3>
                  <span
                    className="text-[10px] font-bold font-mono px-2 py-0.5 rounded border uppercase"
                    style={{ color: scenario.accentColor, borderColor: scenario.accentColor }}
                  >
                    {scenario.mitre}
                  </span>
                </div>
                <p className="text-xs text-[#94A3B8] font-mono leading-relaxed mb-4">{scenario.description}</p>
                <div className="mt-auto">
                  {selectedScenario?.id === scenario.id ? (
                    <span className="text-[11px] font-bold font-mono uppercase tracking-wider" style={{ color: scenario.accentColor }}>
                      SELECTED
                    </span>
                  ) : (
                    <span className="text-[11px] font-bold font-mono uppercase tracking-wider text-[#475569] group-hover:text-[#94A3B8] transition-colors">
                      SELECT
                    </span>
                  )}
                </div>
              </button>
            ))}
          </div>

          {selectedScenario && (
            <div className="flex justify-center pt-2">
              <button
                onClick={handleStartInvestigation}
                className="btn btn-primary flex items-center gap-2"
              >
                <Play className="w-4 h-4" />
                START INVESTIGATION
              </button>
            </div>
          )}
        </div>
      )}

      {/* STEP 2: WATCH PIPELINE */}
      {demoStep === 2 && (
        <div className="space-y-4">
          <ExecutiveSummary />

          {/* Pipeline Visualization */}
          <div className="card-surface p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-[11px] font-bold text-[#475569] uppercase tracking-wider font-mono">
                V2 Pipeline
              </h2>
              <div className="flex items-center gap-2 text-xs font-mono">
                <Clock3 className="w-3 h-3 text-[#00FF88]" />
                <span className="text-[#94A3B8]">{(totalDuration / 1000).toFixed(1)}s</span>
              </div>
            </div>
            <PipelineVisualization stages={pipelineStages} />
          </div>

          {/* Investigation Header */}
          <div className="bg-[#0D1117] border border-[#1B2432] rounded-lg p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <Shield className="w-5 h-5 text-[#00FF88]" />
                  <h1 className="text-lg font-bold text-[#E2E8F0] font-mono">{inv.alert_type}</h1>
                  {isRunning && (
                    <span className="badge badge-executing animate-pulse">
                      INVESTIGATING
                    </span>
                  )}
                </div>
                <p className="text-[#475569] text-xs font-mono">
                  Outbound DNS beaconing to suspicious domain -- automated investigation by ZOVARK
                </p>
              </div>
            </div>

            <div className="flex items-center gap-6 mt-4 pt-4 border-t border-[#1B2432]">
              <div className="flex items-center gap-2 text-xs font-mono">
                <Zap className="w-3.5 h-3.5 text-[#00FF88]" />
                <span className="text-[#475569]">Steps:</span>
                <span className="text-[#E2E8F0] font-bold">{completedSteps} / 7</span>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono">
                <Clock3 className="w-3.5 h-3.5 text-[#00FF88]" />
                <span className="text-[#475569]">Duration:</span>
                <span className="text-[#E2E8F0] font-bold">{(totalDuration / 1000).toFixed(1)}s</span>
              </div>
            </div>
          </div>

          {/* Terminal Log */}
          <TerminalBlock title="investigation.log" lines={terminalLines} maxHeight="280px" />

          {/* Waterfall */}
          <InvestigationWaterfall
            steps={steps}
            isDemo={true}
            onStepClick={setSelectedStep}
          />

          {/* Step Detail Panel */}
          <StepDetailPanel
            step={selectedStep}
            onClose={() => setSelectedStep(null)}
          />
        </div>
      )}

      {/* STEP 3: VERDICT */}
      {demoStep === 3 && (
        <div className="space-y-4">
          <div>
            <h1 className="text-xl font-bold text-[#E2E8F0] font-mono">INVESTIGATION VERDICT</h1>
            <p className="text-[#475569] text-xs mt-1 font-mono uppercase tracking-wider">
              Autonomous analysis complete -- review findings
            </p>
          </div>

          {/* Verdict Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <MetricCard value={92} label="Risk Score" variant="danger" />
            <div className="card-surface p-5 flex flex-col items-center justify-center">
              <StatusBadge status="true_positive" className="text-base" />
              <div className="metric-label mt-3">Verdict</div>
            </div>
            <MetricCard value={`${(inv.confidence * 100).toFixed(0)}%`} label="Confidence" variant="success" />
          </div>

          {/* Risk Bar */}
          <div className="card-surface p-5">
            <div className="flex items-center justify-between mb-3">
              <span className="label">Risk Assessment</span>
              <StatusBadge status="high" />
            </div>
            <RiskBar value={92} />
          </div>

          {/* Findings */}
          <div className="card-surface p-5">
            <h3 className="label mb-3 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 text-[#FF4444]" />
              Key Findings
            </h3>
            <div className="space-y-2">
              {[
                'Host 10.0.5.42 (CORP\\jthompson) beaconing to updateservice-cdn.net every ~30s',
                'Domain registered 3 days ago, 14/72 VirusTotal detections',
                'Resolves to 185.220.101.34 (known Tor exit node, DE)',
                'Process: svchost-update.exe (masquerading as system binary)',
                '119 DNS queries in last hour with 30.2s avg interval (low jitter)',
              ].map((finding, i) => (
                <div key={i} className="flex items-start gap-2 text-xs font-mono text-[#94A3B8]">
                  <span className="text-[#FF4444] mt-0.5 flex-shrink-0">*</span>
                  <span>{finding}</span>
                </div>
              ))}
            </div>
          </div>

          {/* IOCs */}
          <div className="card-surface p-5">
            <h3 className="label mb-3 flex items-center gap-2">
              <Target className="w-3.5 h-3.5 text-[#FFAA00]" />
              IOCs Extracted (5)
            </h3>
            <div className="space-y-1.5">
              {[
                { type: 'DOMAIN', value: 'updateservice-cdn.net', tag: 'MALICIOUS' },
                { type: 'IP', value: '185.220.101.34', tag: 'TOR EXIT' },
                { type: 'IP', value: '10.0.5.42', tag: 'INTERNAL' },
                { type: 'PROCESS', value: 'svchost-update.exe', tag: 'SUSPICIOUS' },
                { type: 'USER', value: 'CORP\\jthompson', tag: 'COMPROMISED' },
              ].map((ioc, i) => (
                <div key={i} className="flex items-center gap-3 text-xs font-mono py-1.5 px-3 rounded bg-[#131B27]">
                  <span className="text-[#475569] min-w-[70px] font-bold">{ioc.type}</span>
                  <span className="text-[#E2E8F0] flex-1">{ioc.value}</span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                    ioc.tag === 'MALICIOUS' || ioc.tag === 'COMPROMISED'
                      ? 'text-[#FF4444] border-[#FF4444]'
                      : ioc.tag === 'TOR EXIT' || ioc.tag === 'SUSPICIOUS'
                        ? 'text-[#FFAA00] border-[#FFAA00]'
                        : 'text-[#475569] border-[#475569]'
                  }`}>
                    {ioc.tag}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE Mapping */}
          <div className="card-surface p-5">
            <h3 className="label mb-3">MITRE ATT&CK</h3>
            <div className="flex flex-wrap gap-2">
              {['T1071.004 - DNS', 'T1568 - DGA', 'T1090 - Proxy'].map((technique) => (
                <span key={technique} className="badge badge-true_positive">{technique}</span>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div className="card-surface p-5">
            <h3 className="label mb-3">Recommended Actions</h3>
            <div className="space-y-2">
              {[
                'Isolate host 10.0.5.42 from network immediately',
                'Block updateservice-cdn.net and 185.220.101.34 at perimeter firewall',
                'Reset credentials for CORP\\jthompson',
                'Forensic image of 10.0.5.42 for further analysis',
                'Hunt for svchost-update.exe across enterprise',
              ].map((rec, i) => (
                <div key={i} className="flex items-start gap-2 text-xs font-mono text-[#94A3B8]">
                  <span className="text-[#00FF88] mt-0.5 flex-shrink-0">{i + 1}.</span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button onClick={() => setDemoStep(4)} className="btn btn-primary">
              VIEW PATH PROMOTION
              <ChevronRight className="w-4 h-4" />
            </button>
            <button onClick={handleRestart} className="btn btn-secondary">
              <RotateCcw className="w-4 h-4" />
              RESTART DEMO
            </button>
          </div>
        </div>
      )}

      {/* STEP 4: PROMOTE */}
      {demoStep === 4 && (
        <div className="space-y-4">
          <div>
            <h1 className="text-xl font-bold text-[#E2E8F0] font-mono">PATH PROMOTION</h1>
            <p className="text-[#475569] text-xs mt-1 font-mono uppercase tracking-wider">
              Convert LLM-generated investigation into a reusable template
            </p>
          </div>

          {/* Before / After comparison */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* BEFORE */}
            <div className="card-surface p-5 border-l-2" style={{ borderLeftColor: '#FFAA00' }}>
              <h3 className="label mb-4 text-[#FFAA00]">BEFORE (Path C)</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">Execution Path</span>
                  <span className="text-[#FFAA00] font-bold">PATH C: LLM GEN</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">Response Time</span>
                  <span className="text-[#FFAA00] font-bold">~120s</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">LLM Calls</span>
                  <span className="text-[#FFAA00] font-bold">2 (gen + assess)</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">Analyst Review</span>
                  <span className="text-[#FFAA00] font-bold">REQUIRED</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">GPU Utilization</span>
                  <span className="text-[#FFAA00] font-bold">HIGH</span>
                </div>
              </div>
            </div>

            {/* AFTER */}
            <div className="card-surface p-5 border-l-2" style={{ borderLeftColor: '#00FF88' }}>
              <h3 className="label mb-4 text-[#00FF88]">AFTER (Path A)</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">Execution Path</span>
                  <span className="text-[#00FF88] font-bold">PATH A: TEMPLATE</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">Response Time</span>
                  <span className="text-[#00FF88] font-bold">~350ms</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">LLM Calls</span>
                  <span className="text-[#00FF88] font-bold">1 (assess only)</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">Analyst Review</span>
                  <span className="text-[#00FF88] font-bold">AUTO-RESOLVED</span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-[#475569]">GPU Utilization</span>
                  <span className="text-[#00FF88] font-bold">MINIMAL</span>
                </div>
              </div>
            </div>
          </div>

          {/* Speed improvement */}
          <div className="card-surface p-5">
            <h3 className="label mb-3">Performance Improvement</h3>
            <div className="grid grid-cols-3 gap-4">
              <MetricCard value="343x" label="Faster" variant="success" />
              <MetricCard value="50%" label="Less LLM Cost" variant="success" />
              <MetricCard value="0" label="Analyst Review" variant="success" />
            </div>
          </div>

          {/* Promote button */}
          <div className="card-surface p-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold font-mono text-[#E2E8F0]">Promote to Template</h3>
                <p className="text-xs font-mono text-[#475569] mt-1">
                  Save the validated Path C investigation code as a reusable skill template.
                  All future alerts of this type will use Path A fast-fill (~350ms).
                </p>
              </div>
              <button className="btn btn-primary">
                <Zap className="w-4 h-4" />
                PROMOTE TO TEMPLATE
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button onClick={() => setDemoStep(3)} className="btn btn-secondary">
              BACK TO VERDICT
            </button>
            <button onClick={handleRestart} className="btn btn-secondary">
              <RotateCcw className="w-4 h-4" />
              RESTART DEMO
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
