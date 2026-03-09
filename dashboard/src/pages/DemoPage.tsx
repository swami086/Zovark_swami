import { useState } from 'react';
import { useDemo } from '../hooks/useDemo';
import InvestigationWaterfall from '../components/InvestigationWaterfall';
import StepDetailPanel from '../components/StepDetailPanel';
import DemoBanner from '../components/DemoBanner';
import DemoSelector from '../components/DemoSelector';
import { C2_BEACON_INVESTIGATION } from '../demo/c2BeaconScenario';
import type { WorkflowStep } from '../types';
import { Shield, Clock3, Target, Zap } from 'lucide-react';

export default function DemoPage() {
  const { steps, isRunning, isComplete, startDemo } = useDemo();
  const [selectedStep, setSelectedStep] = useState<WorkflowStep | null>(null);
  const [hasStarted, setHasStarted] = useState(false);

  const handleStart = () => {
    setHasStarted(true);
    setSelectedStep(null);
    startDemo();
  };

  if (!hasStarted) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Demo Mode</h1>
            <p className="text-slate-400 mt-1">Experience HYDRA's autonomous investigation capabilities</p>
          </div>
        </div>
        <DemoSelector onStart={handleStart} />
      </div>
    );
  }

  const inv = C2_BEACON_INVESTIGATION;
  const completedSteps = steps.filter(s => s.status === 'completed').length;
  const totalDuration = steps
    .filter(s => s.status === 'completed')
    .reduce((sum, s) => sum + (s.duration_ms || 0), 0);

  return (
    <div className="space-y-4">
      <DemoBanner />

      {/* Investigation Header */}
      <div className="bg-[#1E293B] border border-slate-700/50 rounded-lg p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <h1 className="text-xl font-bold text-white">{inv.alert_type}</h1>
              {isComplete && (
                <span className="px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  {inv.verdict.toUpperCase()}
                </span>
              )}
              {isRunning && (
                <span className="px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse">
                  INVESTIGATING
                </span>
              )}
            </div>
            <p className="text-slate-400 text-sm">
              Outbound DNS beaconing to suspicious domain — automated investigation by HYDRA
            </p>
          </div>
          {!isRunning && hasStarted && (
            <button
              onClick={handleStart}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              Restart Demo
            </button>
          )}
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-6 mt-4 pt-4 border-t border-slate-700/50">
          <div className="flex items-center gap-2 text-sm">
            <Zap className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">Steps:</span>
            <span className="text-white font-medium">{completedSteps} / 7</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Clock3 className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">Duration:</span>
            <span className="text-white font-medium">{(totalDuration / 1000).toFixed(1)}s</span>
          </div>
          {isComplete && (
            <>
              <div className="flex items-center gap-2 text-sm">
                <Target className="w-4 h-4 text-cyan-400" />
                <span className="text-slate-400">Confidence:</span>
                <span className="text-white font-medium">{(inv.confidence * 100).toFixed(0)}%</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="text-slate-400">Severity:</span>
                <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/20 uppercase">
                  {inv.severity}
                </span>
              </div>
            </>
          )}
        </div>
      </div>

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
  );
}
