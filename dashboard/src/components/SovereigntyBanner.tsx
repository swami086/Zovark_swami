import { Lock } from 'lucide-react';

export default function SovereigntyBanner() {
  return (
    <div className="flex items-center justify-between bg-[#1E293B]/60 border border-slate-700/30 rounded-lg px-5 py-3">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <span className="text-emerald-400 font-medium">Local VPC Processing</span>
        <span className="text-slate-600">&rarr;</span>
        <span className="text-blue-400 font-medium">LLM Enrichment</span>
        <span className="text-slate-600">&rarr;</span>
        <span className="text-emerald-400 font-medium">Local Report</span>
      </div>
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Lock className="w-3.5 h-3.5 text-emerald-400" />
        <span>Zero PII sent to cloud</span>
      </div>
    </div>
  );
}
