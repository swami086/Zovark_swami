interface GuardrailScoreBarProps {
  score: number;
  threshold?: number;
  passed: boolean;
}

export default function GuardrailScoreBar({ score, threshold, passed }: GuardrailScoreBarProps) {
  return (
    <div className="space-y-1.5">
      {/* Bar */}
      <div className="relative h-3 bg-slate-700 rounded-full overflow-visible">
        {/* Fill */}
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${
            passed ? 'bg-emerald-500' : 'bg-rose-500'
          }`}
          style={{ width: `${Math.min(Math.max(score, 0), 100)}%` }}
        />

        {/* Threshold marker */}
        {threshold !== undefined && (
          <div
            className="absolute top-[-4px] bottom-[-4px] border-l-2 border-dashed border-amber-400"
            style={{ left: `${threshold}%` }}
            title={`Threshold: ${threshold}`}
          />
        )}
      </div>

      {/* Labels */}
      <div className="flex items-center justify-between">
        <span
          className={`text-xs font-semibold tracking-wide uppercase ${
            passed ? 'text-emerald-400' : 'text-rose-400'
          }`}
        >
          {passed ? 'PASSED' : 'FAILED \u2014 triggering retry'}
        </span>
        <span className="text-sm font-mono text-slate-300">
          {score} / 100
        </span>
      </div>
    </div>
  );
}
