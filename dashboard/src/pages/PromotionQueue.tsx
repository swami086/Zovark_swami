import { useEffect, useState, useCallback } from 'react';
import { Sparkles, RefreshCw, CheckCircle, XCircle, ChevronDown, ChevronUp, Code2, AlertTriangle, Eye } from 'lucide-react';
import { fetchPromotionQueue, submitAnalystFeedback, type PromotionItem } from '../api/client';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import MetricCard from '../components/MetricCard';
import StatusBadge from '../components/StatusBadge';
import RiskBar from '../components/RiskBar';
import PipelineVisualization from '../components/PipelineVisualization';
import TerminalBlock from '../components/TerminalBlock';
import { Skeleton } from '../components/Skeleton';
import { formatDistanceToNow } from 'date-fns';
import '../styles/design-system.css';

export default function PromotionQueue() {
  const [items, setItems] = useState<PromotionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [awaitingReview, setAwaitingReview] = useState(0);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [expandedSections, setExpandedSections] = useState<Record<string, Set<string>>>({});
  const [submittingIds, setSubmittingIds] = useState<Set<string>>(new Set());
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [confirmAction, setConfirmAction] = useState<{ taskId: string; action: string } | null>(null);

  const loadQueue = useCallback(async () => {
    try {
      const data = await fetchPromotionQueue();
      setItems(data.items || []);
      setAwaitingReview(data.awaiting_review || 0);
    } catch (err: any) {
      setError(err.message || 'Failed to load promotion queue');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadQueue();
    const interval = setInterval(loadQueue, 15000);
    return () => clearInterval(interval);
  }, [loadQueue]);

  const toggleExpanded = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSection = (itemId: string, section: string) => {
    setExpandedSections(prev => {
      const existing = prev[itemId] || new Set();
      const next = new Set(existing);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return { ...prev, [itemId]: next };
    });
  };

  const isSectionOpen = (itemId: string, section: string) => {
    return expandedSections[itemId]?.has(section) || false;
  };

  const handleAction = async (taskId: string, action: string) => {
    setSubmittingIds(prev => new Set(prev).add(taskId));
    try {
      const feedbackMap: Record<string, { analyst_verdict: string; promote?: boolean }> = {
        'confirm_promote': { analyst_verdict: 'confirmed', promote: true },
        'confirm': { analyst_verdict: 'confirmed', promote: false },
        'override': { analyst_verdict: 'overridden', promote: false },
        'reject': { analyst_verdict: 'rejected', promote: false },
      };

      const fb = feedbackMap[action] || { analyst_verdict: action };

      await submitAnalystFeedback({
        task_id: taskId,
        analyst_verdict: fb.analyst_verdict,
        analyst_notes: notes[taskId] || undefined,
        promote: fb.promote,
      });

      setItems(prev => prev.filter(i => i.task_id !== taskId));
      setConfirmAction(null);
    } catch (err: any) {
      alert(err.message || 'Failed to submit feedback');
    } finally {
      setSubmittingIds(prev => {
        const next = new Set(prev);
        next.delete(taskId);
        return next;
      });
    }
  };

  // Calculate stats
  const promoted = items.filter(i => i.verdict === 'true_positive').length;
  const totalReviewed = items.length;
  const confirmRate = totalReviewed > 0 ? Math.round((promoted / totalReviewed) * 100) : 0;

  return (
    <div className="war-room space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center" style={{ color: 'var(--text-primary)' }}>
            <Sparkles className="w-6 h-6 mr-3" style={{ color: 'var(--accent-green)' }} />
            Promotion Queue
          </h1>
          <p className="body-text mt-1">Review Path C investigations for template promotion</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="label">Auto-refreshes every 15s</span>
          <button
            onClick={() => { setLoading(true); loadQueue(); }}
            className="btn btn-secondary btn-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="card-surface p-4" style={{ borderColor: 'var(--accent-red)', color: 'var(--accent-red)' }}>
          {error}
        </div>
      )}

      {/* Summary metrics */}
      <div className="grid grid-cols-3 gap-4">
        <MetricCard
          value={loading ? '-' : awaitingReview}
          label="Awaiting Review"
          variant="warning"
        />
        <MetricCard
          value={loading ? '-' : promoted}
          label="Promoted"
          variant="success"
        />
        <MetricCard
          value={loading ? '-' : `${confirmRate}%`}
          label="Confirm Rate"
          variant="default"
        />
      </div>

      {/* Pipeline overview */}
      <div className="card-surface p-4">
        <div className="label mb-3">V2 Pipeline</div>
        <PipelineVisualization
          stages={{
            INGEST: 'completed',
            ANALYZE: 'completed',
            EXECUTE: 'completed',
            ASSESS: 'completed',
            STORE: 'active',
          }}
        />
      </div>

      {/* Items */}
      {loading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="card-surface p-6 space-y-4 animate-pulse">
              <Skeleton className="h-5 w-64" />
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-20 w-full" />
            </div>
          ))}
        </div>
      ) : items.length === 0 ? (
        <div className="card-surface p-12 text-center">
          <CheckCircle className="w-12 h-12 mx-auto mb-4" style={{ color: 'var(--accent-green)' }} />
          <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>Queue Clear</h3>
          <p className="body-text">No Path C investigations awaiting review.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {items.map(item => {
            const isExpanded = expandedIds.has(item.task_id);
            const isSubmitting = submittingIds.has(item.task_id);

            return (
              <div key={item.task_id} className="card-surface overflow-hidden">
                {/* Card header */}
                <div className="p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <StatusBadge status={item.verdict || 'pending'} />
                        <span className="label" style={{ color: 'var(--accent-cyan)' }}>
                          Path {item.path_taken}
                        </span>
                        <span className="label">
                          {formatDistanceToNow(new Date(item.created_at), { addSuffix: true })}
                        </span>
                      </div>
                      <h3 className="text-sm font-semibold mb-1" style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                        {item.task_type.replace(/_/g, ' ')}
                      </h3>
                      <span className="label">Task {item.task_id.slice(0, 8)}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <RiskBar value={item.risk_score} className="w-32" />
                      {item.execution_ms && (
                        <span className="label">{(item.execution_ms / 1000).toFixed(1)}s</span>
                      )}
                    </div>
                  </div>

                  {/* MITRE tags */}
                  {item.mitre_attack && item.mitre_attack.length > 0 && (
                    <div className="flex flex-wrap gap-2 mb-3">
                      {item.mitre_attack.map((t, i) => (
                        <span key={i} className="badge badge-executing">{t}</span>
                      ))}
                    </div>
                  )}

                  {/* Toggle expand */}
                  <button
                    onClick={() => toggleExpanded(item.task_id)}
                    className="flex items-center space-x-1 expand-toggle"
                    style={{ color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>{isExpanded ? 'Collapse' : 'Expand'} Details</span>
                    {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>

                  {/* Expanded content */}
                  {isExpanded && (
                    <div className="mt-4 space-y-3">
                      {/* SIEM Event section */}
                      {item.siem_event && (
                        <div>
                          <button
                            onClick={() => toggleSection(item.task_id, 'siem')}
                            className="flex items-center space-x-1 expand-toggle label mb-2"
                          >
                            {isSectionOpen(item.task_id, 'siem') ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            <span>SIEM Event</span>
                          </button>
                          {isSectionOpen(item.task_id, 'siem') && (
                            <TerminalBlock title="siem_event.json">
                              <pre style={{ fontSize: '12px', color: 'var(--accent-green)' }}>
                                {JSON.stringify(item.siem_event, null, 2)}
                              </pre>
                            </TerminalBlock>
                          )}
                        </div>
                      )}

                      {/* Generated code section */}
                      {item.generated_code && (
                        <div>
                          <button
                            onClick={() => toggleSection(item.task_id, 'code')}
                            className="flex items-center space-x-1 expand-toggle label mb-2"
                          >
                            <Code2 className="w-3 h-3" />
                            {isSectionOpen(item.task_id, 'code') ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            <span>Generated Code</span>
                          </button>
                          {isSectionOpen(item.task_id, 'code') && (
                            <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--border-default)' }}>
                              <SyntaxHighlighter
                                language="python"
                                style={atomDark}
                                customStyle={{ margin: 0, fontSize: '12px', maxHeight: '300px', background: 'var(--bg-surface)' }}
                              >
                                {item.generated_code}
                              </SyntaxHighlighter>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Findings section */}
                      {item.findings && item.findings.length > 0 && (
                        <div>
                          <button
                            onClick={() => toggleSection(item.task_id, 'findings')}
                            className="flex items-center space-x-1 expand-toggle label mb-2"
                          >
                            <AlertTriangle className="w-3 h-3" />
                            {isSectionOpen(item.task_id, 'findings') ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            <span>Findings ({item.findings.length})</span>
                          </button>
                          {isSectionOpen(item.task_id, 'findings') && (
                            <TerminalBlock title="findings">
                              <pre style={{ fontSize: '12px' }}>
                                {JSON.stringify(item.findings, null, 2)}
                              </pre>
                            </TerminalBlock>
                          )}
                        </div>
                      )}

                      {/* IOCs section */}
                      {item.iocs && item.iocs.length > 0 && (
                        <div>
                          <button
                            onClick={() => toggleSection(item.task_id, 'iocs')}
                            className="flex items-center space-x-1 expand-toggle label mb-2"
                          >
                            {isSectionOpen(item.task_id, 'iocs') ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            <span>IOCs ({item.iocs.length})</span>
                          </button>
                          {isSectionOpen(item.task_id, 'iocs') && (
                            <TerminalBlock title="iocs">
                              <pre style={{ fontSize: '12px', color: 'var(--accent-red)' }}>
                                {JSON.stringify(item.iocs, null, 2)}
                              </pre>
                            </TerminalBlock>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Action bar */}
                <div
                  className="px-5 py-4 flex items-center justify-between"
                  style={{
                    background: 'var(--bg-base)',
                    borderTop: '1px solid var(--border-default)',
                  }}
                >
                  <div>
                    <input
                      type="text"
                      placeholder="Analyst notes (optional)..."
                      value={notes[item.task_id] || ''}
                      onChange={e => setNotes(prev => ({ ...prev, [item.task_id]: e.target.value }))}
                      className="bg-transparent border rounded-lg px-3 py-2 text-xs focus:outline-none w-80"
                      style={{
                        fontFamily: 'var(--font-mono)',
                        borderColor: 'var(--border-default)',
                        color: 'var(--text-secondary)',
                      }}
                    />
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      disabled={isSubmitting}
                      onClick={() => setConfirmAction({ taskId: item.task_id, action: 'reject' })}
                      className="btn btn-danger btn-sm"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>
                    <button
                      disabled={isSubmitting}
                      onClick={() => setConfirmAction({ taskId: item.task_id, action: 'override' })}
                      className="btn btn-warning btn-sm"
                    >
                      <span>Override</span>
                    </button>
                    <button
                      disabled={isSubmitting}
                      onClick={() => handleAction(item.task_id, 'confirm')}
                      className="btn btn-info btn-sm"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      <span>Confirm</span>
                    </button>
                    <button
                      disabled={isSubmitting}
                      onClick={() => setConfirmAction({ taskId: item.task_id, action: 'confirm_promote' })}
                      className="btn btn-primary btn-sm"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Confirm & Promote</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Confirmation modal */}
      {confirmAction && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: 'var(--bg-overlay)' }}
        >
          <div className="card-elevated w-full max-w-md shadow-2xl p-6">
            <h3 className="text-lg font-bold mb-3" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
              {confirmAction.action === 'reject'
                ? 'Confirm Rejection'
                : confirmAction.action === 'override'
                  ? 'Confirm Override'
                  : 'Confirm & Promote to Template'}
            </h3>
            <p className="body-text mb-6">
              {confirmAction.action === 'reject'
                ? 'This will reject the investigation result and prevent template promotion.'
                : confirmAction.action === 'override'
                  ? 'This will override the LLM verdict with your analyst assessment.'
                  : 'This will confirm the result and promote it as a new skill template for future investigations.'}
            </p>
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setConfirmAction(null)}
                className="btn btn-ghost"
              >
                Cancel
              </button>
              <button
                onClick={() => handleAction(confirmAction.taskId, confirmAction.action)}
                className={`btn ${
                  confirmAction.action === 'reject'
                    ? 'btn-danger'
                    : confirmAction.action === 'override'
                      ? 'btn-warning'
                      : 'btn-primary'
                }`}
              >
                {submittingIds.has(confirmAction.taskId) && (
                  <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                )}
                {confirmAction.action === 'reject' ? 'Yes, Reject' : confirmAction.action === 'override' ? 'Yes, Override' : 'Yes, Promote'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
