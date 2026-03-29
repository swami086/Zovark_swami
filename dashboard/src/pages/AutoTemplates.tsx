import { useEffect, useState, useCallback } from 'react';
import { Layers, RefreshCw, Trash2, ChevronDown, ChevronUp } from 'lucide-react';
import { fetchAutoTemplates, disableAutoTemplate, type AutoTemplate } from '../api/client';
import StatusBadge from '../components/StatusBadge';
import TerminalBlock from '../components/TerminalBlock';
import { Skeleton } from '../components/Skeleton';
import { formatDistanceToNow } from 'date-fns';
import '../styles/design-system.css';

export default function AutoTemplates() {
  const [templates, setTemplates] = useState<AutoTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedSlug, setExpandedSlug] = useState<string | null>(null);
  const [disablingSlug, setDisablingSlug] = useState<string | null>(null);
  const [confirmDisable, setConfirmDisable] = useState<string | null>(null);

  const loadTemplates = useCallback(async () => {
    try {
      const data = await fetchAutoTemplates();
      setTemplates(data.items || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load auto templates');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTemplates();
    const interval = setInterval(loadTemplates, 30000);
    return () => clearInterval(interval);
  }, [loadTemplates]);

  const handleDisable = async (slug: string) => {
    setDisablingSlug(slug);
    try {
      await disableAutoTemplate(slug);
      setTemplates(prev => prev.filter(t => t.slug !== slug));
      setConfirmDisable(null);
    } catch (err: any) {
      alert(err.message || 'Failed to disable template');
    } finally {
      setDisablingSlug(null);
    }
  };

  const toggleExpand = (slug: string) => {
    setExpandedSlug(prev => prev === slug ? null : slug);
  };

  return (
    <div className="war-room space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center" style={{ color: 'var(--text-primary)' }}>
            <Layers className="w-6 h-6 mr-3" style={{ color: 'var(--accent-green)' }} />
            Auto Templates
          </h1>
          <p className="body-text mt-1">Auto-promoted skill templates from confirmed Path C investigations</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="label">Auto-refreshes every 30s</span>
          <button
            onClick={() => { setLoading(true); loadTemplates(); }}
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

      {/* Summary */}
      <div className="flex items-center gap-4">
        <div className="label">
          Total: <span style={{ color: 'var(--text-primary)' }}>{loading ? '-' : templates.length}</span>
        </div>
        <div className="label">
          Active: <span style={{ color: 'var(--accent-green)' }}>
            {loading ? '-' : templates.filter(t => t.status === 'active' || t.auto_promoted).length}
          </span>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="card-surface p-6 space-y-4 animate-pulse">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : templates.length === 0 ? (
        <div className="card-surface p-12 text-center">
          <Layers className="w-12 h-12 mx-auto mb-4" style={{ color: 'var(--text-muted)' }} />
          <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>No Auto Templates</h3>
          <p className="body-text">Templates will appear here once Path C investigations are confirmed and promoted.</p>
        </div>
      ) : (
        <div className="card-surface overflow-hidden">
          {/* Table header */}
          <div
            className="grid grid-cols-12 gap-2 px-5 py-3"
            style={{ borderBottom: '1px solid var(--border-default)', background: 'var(--bg-elevated)' }}
          >
            <div className="col-span-3 label">Slug</div>
            <div className="col-span-2 label">Task Types</div>
            <div className="col-span-2 label">Status</div>
            <div className="col-span-2 label">Promoted</div>
            <div className="col-span-2 label">Promoted By</div>
            <div className="col-span-1 label text-right">Actions</div>
          </div>

          {/* Table rows */}
          {templates.map(template => {
            const isExpanded = expandedSlug === template.slug;
            const isDisabling = disablingSlug === template.slug;

            return (
              <div key={template.slug}>
                <div
                  className="grid grid-cols-12 gap-2 px-5 py-3 items-center row-hover expand-toggle"
                  style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  onClick={() => toggleExpand(template.slug)}
                >
                  <div className="col-span-3 flex items-center gap-2">
                    {isExpanded
                      ? <ChevronUp className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
                      : <ChevronDown className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
                    }
                    <span
                      className="text-sm font-medium truncate"
                      style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}
                    >
                      {template.slug}
                    </span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-xs" style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {template.task_types?.join(', ') || '-'}
                    </span>
                  </div>
                  <div className="col-span-2">
                    <StatusBadge status={template.status === 'active' ? 'completed' : template.status || 'pending'} />
                  </div>
                  <div className="col-span-2">
                    <span className="label">
                      {template.promoted_at
                        ? formatDistanceToNow(new Date(template.promoted_at), { addSuffix: true })
                        : '-'}
                    </span>
                  </div>
                  <div className="col-span-2">
                    <span className="label" style={{ color: 'var(--text-secondary)' }}>
                      {template.promoted_by || '-'}
                    </span>
                  </div>
                  <div className="col-span-1 text-right" onClick={e => e.stopPropagation()}>
                    <button
                      disabled={isDisabling}
                      onClick={() => setConfirmDisable(template.slug)}
                      className="btn btn-danger btn-sm"
                      title="Disable template"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                {/* Expanded row — show templatized code */}
                {isExpanded && (
                  <div className="px-5 py-4" style={{ background: 'var(--bg-base)', borderBottom: '1px solid var(--border-default)' }}>
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div>
                        <span className="label">Name</span>
                        <p className="text-sm mt-1" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                          {template.name}
                        </p>
                      </div>
                      <div>
                        <span className="label">Source Task</span>
                        <p className="text-sm mt-1" style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                          {template.source_task_id?.slice(0, 12) || '-'}
                        </p>
                      </div>
                    </div>

                    <div className="label mb-2">Task Types</div>
                    <div className="flex flex-wrap gap-2 mb-4">
                      {template.task_types?.map((tt, i) => (
                        <span key={i} className="badge badge-executing">{tt}</span>
                      )) || <span className="body-text">None</span>}
                    </div>

                    <div className="label mb-2">Templatized Code</div>
                    <TerminalBlock title={`${template.slug}.py`} maxHeight="300px">
                      <pre style={{ fontSize: '12px', color: 'var(--accent-green)' }}>
                        {`# Auto-promoted template: ${template.slug}\n# Source: task ${template.source_task_id || 'unknown'}\n# Promoted by: ${template.promoted_by || 'system'}\n\nimport json\n\nsiem_event = json.loads('''{{siem_event_json}}''')\n\n# Template code will be populated from\n# the original Path C investigation\n# after analyst confirmation.\n\nresult = {\n    "findings": [],\n    "iocs": [],\n    "risk_score": 0,\n    "verdict": "benign",\n    "investigation_type": "${template.slug}"\n}\nprint(json.dumps(result))`}
                      </pre>
                    </TerminalBlock>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Confirm disable modal */}
      {confirmDisable && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: 'var(--bg-overlay)' }}
        >
          <div className="card-elevated w-full max-w-md shadow-2xl p-6">
            <h3 className="text-lg font-bold mb-3" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
              Disable Template
            </h3>
            <p className="body-text mb-2">
              Are you sure you want to disable the template:
            </p>
            <p className="mb-6" style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-red)', fontSize: '14px' }}>
              {confirmDisable}
            </p>
            <p className="body-text mb-6">
              Future alerts matching this template will fall through to Path C (full LLM generation).
            </p>
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setConfirmDisable(null)}
                className="btn btn-ghost"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDisable(confirmDisable)}
                className="btn btn-danger"
              >
                {disablingSlug === confirmDisable && (
                  <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                )}
                Yes, Disable
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
