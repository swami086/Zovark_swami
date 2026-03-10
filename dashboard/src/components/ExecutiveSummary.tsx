import { ShieldCheck, Clock3, TrendingUp, DollarSign } from 'lucide-react';

const metrics = [
  { label: 'Alerts Auto-Triaged', value: '1,204', icon: ShieldCheck, color: 'text-cyan-400' },
  { label: 'Analyst Hours Saved', value: '340', icon: Clock3, color: 'text-emerald-400' },
  { label: 'Mean Time to Respond', value: '8.2s', icon: TrendingUp, color: 'text-violet-400' },
  { label: 'Cost Avoided', value: '$127,200', icon: DollarSign, color: 'text-amber-400' },
];

export default function ExecutiveSummary() {
  return (
    <div className="bg-[#0F172A] border border-slate-700/50 rounded-lg p-5">
      <div className="flex items-center justify-between">
        <div className="grid grid-cols-4 gap-6 flex-1">
          {metrics.map((m) => (
            <div key={m.label} className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-800/80">
                <m.icon className={`w-5 h-5 ${m.color}`} />
              </div>
              <div>
                <p className="text-white text-lg font-bold leading-tight">{m.value}</p>
                <p className="text-slate-500 text-xs">{m.label}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-2 ml-6 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="text-emerald-400 text-xs font-semibold whitespace-nowrap">All data processed locally</span>
        </div>
      </div>
    </div>
  );
}
