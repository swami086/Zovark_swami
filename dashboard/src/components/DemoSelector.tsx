import { Shield } from 'lucide-react';

interface DemoSelectorProps {
  onStart?: () => void;
}

export default function DemoSelector({ onStart }: DemoSelectorProps) {

  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="bg-[#0F172A] border border-slate-700/50 rounded-xl p-8 max-w-lg w-full text-center space-y-6">
        {/* Title */}
        <div className="flex items-center justify-center space-x-3">
          <Shield className="w-7 h-7 text-cyan-500" />
          <h2 className="text-xl font-bold text-white tracking-wide">Run Demo Investigation</h2>
        </div>

        {/* Description */}
        <p className="text-slate-400 leading-relaxed">
          Watch HYDRA autonomously investigate a C2 beacon alert in real-time
        </p>

        {/* Start button */}
        <button
          onClick={() => onStart?.()}
          className="bg-cyan-600 hover:bg-cyan-500 text-white px-6 py-3 rounded-lg font-semibold transition-colors duration-200"
        >
          Start C2 Beacon Demo
        </button>

        {/* Steps preview */}
        <div className="text-left bg-slate-800/50 rounded-lg p-4 space-y-1">
          <p className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">
            What will happen
          </p>
          <ul className="text-sm text-slate-400 space-y-1 list-none">
            <li className="flex items-start space-x-2">
              <span className="text-cyan-500 font-mono text-xs mt-0.5">1.</span>
              <span>Parse incoming SIEM alert</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-500 font-mono text-xs mt-0.5">2.</span>
              <span>Generate Python investigation code via LLM</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-500 font-mono text-xs mt-0.5">3.</span>
              <span>Execute code in sandboxed container</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-500 font-mono text-xs mt-0.5">4.</span>
              <span>Extract entities (IPs, domains, hashes)</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-500 font-mono text-xs mt-0.5">5.</span>
              <span>Run guardrail quality validation</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-500 font-mono text-xs mt-0.5">6.</span>
              <span>Deep analysis and enrichment</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-cyan-500 font-mono text-xs mt-0.5">7.</span>
              <span>Generate incident report</span>
            </li>
          </ul>
          <p className="text-xs text-slate-500 mt-3 pt-2 border-t border-slate-700/50">
            Total duration: ~9 seconds (simulated)
          </p>
        </div>
      </div>
    </div>
  );
}
