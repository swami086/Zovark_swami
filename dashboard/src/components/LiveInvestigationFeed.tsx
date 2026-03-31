import { useEffect, useState, useRef } from 'react';

interface InvestigationEvent {
  event_type: string;
  task_id: string;
  trace_id: string;
  timestamp: string;
  data: Record<string, unknown>;
}

interface LiveInvestigationFeedProps {
  taskId: string;
  token: string;
}

const eventIcon: Record<string, string> = {
  stage_started: '⬇',
  stage_completed: '✓',
  path_selected: '🔍',
  tool_started: '⚙',
  tool_completed: '⚙',
  ioc_discovered: '🔴',
  mitre_mapped: '🗂',
  verdict_ready: '⚡',
  investigation_complete: '✅',
};

const verdictColor: Record<string, string> = {
  true_positive: 'text-rose-400',
  suspicious: 'text-amber-400',
  benign: 'text-emerald-400',
  inconclusive: 'text-slate-400',
  error: 'text-slate-500',
};

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
  } catch {
    return '';
  }
}

function describeEvent(evt: InvestigationEvent): string {
  const d = evt.data;
  switch (evt.event_type) {
    case 'tool_started': return `Running ${d.tool}...`;
    case 'tool_completed': return `${d.tool} — ${d.summary || `${d.duration_ms}ms`}`;
    case 'ioc_discovered': return `IOC: ${d.ioc_type} ${d.value}`;
    case 'mitre_mapped': return `MITRE: ${d.technique_id} — ${d.name}`;
    case 'verdict_ready': return `Verdict: ${d.verdict} (risk: ${d.risk_score})`;
    case 'stage_started': return `${String(d.stage || '').toUpperCase()} starting...`;
    case 'stage_completed': return `${String(d.stage || '').toUpperCase()} done (${d.duration_ms}ms)`;
    case 'path_selected': return `Path ${d.path} selected${d.plan_name ? ` (${d.plan_name})` : ''}`;
    case 'investigation_complete': return `Complete in ${d.total_time_ms}ms`;
    default: return evt.event_type;
  }
}

export default function LiveInvestigationFeed({ taskId, token }: LiveInvestigationFeedProps) {
  const [events, setEvents] = useState<InvestigationEvent[]>([]);
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8090';
    const url = `${apiBase}/api/v1/tasks/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);

    const handleEvent = (e: MessageEvent) => {
      try {
        const parsed: InvestigationEvent = JSON.parse(e.data);
        if (parsed.task_id === taskId) {
          setEvents(prev => [...prev, parsed]);
        }
      } catch { /* ignore malformed events */ }
    };

    // Listen to all waterfall event types
    const types = ['tool_started', 'tool_completed', 'ioc_discovered', 'mitre_mapped',
      'verdict_ready', 'stage_started', 'stage_completed', 'path_selected', 'investigation_complete'];
    types.forEach(t => es.addEventListener(t, handleEvent));
    // Also listen to generic message
    es.onmessage = handleEvent;

    return () => {
      es.close();
    };
  }, [taskId, token]);

  // Auto-scroll
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events]);

  if (events.length === 0) {
    return (
      <div className="text-slate-500 text-sm font-mono p-4">
        Waiting for investigation events...
      </div>
    );
  }

  return (
    <div ref={feedRef} className="max-h-96 overflow-y-auto space-y-1 p-3 font-mono text-sm bg-[#0a0f1a] rounded-lg border border-slate-700/50">
      {events.map((evt, i) => {
        const icon = eventIcon[evt.event_type] || '•';
        const isVerdict = evt.event_type === 'verdict_ready';
        const isTool = evt.event_type.startsWith('tool_');
        const isIOC = evt.event_type === 'ioc_discovered';

        return (
          <div
            key={i}
            className={`flex items-start gap-2 animate-fadeIn ${isTool ? 'pl-4' : ''} ${isIOC ? 'text-amber-300' : ''} ${isVerdict ? verdictColor[String(evt.data.verdict)] || '' : 'text-slate-300'}`}
            style={{ animationDelay: `${i * 50}ms` }}
          >
            <span className="text-slate-500 shrink-0 w-24">{formatTime(evt.timestamp)}</span>
            <span className="shrink-0 w-5 text-center">{icon}</span>
            <span className={isVerdict ? 'font-bold' : ''}>{describeEvent(evt)}</span>
          </div>
        );
      })}
    </div>
  );
}
