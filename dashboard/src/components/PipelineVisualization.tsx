import { CheckCircle } from 'lucide-react';
import '../styles/design-system.css';

type StageStatus = 'queued' | 'active' | 'completed' | 'failed';

interface PipelineVisualizationProps {
  /** Map of stage name to its status. Order: INGEST, ANALYZE, EXECUTE, ASSESS, STORE */
  stages?: Record<string, StageStatus>;
  className?: string;
}

const STAGE_NAMES = ['INGEST', 'ANALYZE', 'EXECUTE', 'ASSESS', 'STORE'];

const defaultStages: Record<string, StageStatus> = {
  INGEST: 'queued',
  ANALYZE: 'queued',
  EXECUTE: 'queued',
  ASSESS: 'queued',
  STORE: 'queued',
};

export default function PipelineVisualization({ stages = defaultStages, className = '' }: PipelineVisualizationProps) {
  const statusClass = (status: StageStatus) => {
    switch (status) {
      case 'active': return 'pipeline-stage-active';
      case 'completed': return 'pipeline-stage-completed';
      case 'failed': return 'pipeline-stage-failed';
      default: return 'pipeline-stage-queued';
    }
  };

  const connectorClass = (idx: number) => {
    const currentStage = STAGE_NAMES[idx];
    const status = stages[currentStage] || 'queued';
    return status === 'completed' || status === 'active'
      ? 'pipeline-connector pipeline-connector-active'
      : 'pipeline-connector';
  };

  return (
    <div className={`flex items-center justify-center flex-wrap gap-y-2 ${className}`}>
      {STAGE_NAMES.map((name, idx) => {
        const status = stages[name] || 'queued';
        return (
          <div key={name} className="flex items-center">
            <div className={`pipeline-stage ${statusClass(status)}`}>
              {status === 'completed' ? (
                <span className="flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" />
                  {name}
                </span>
              ) : (
                name
              )}
            </div>
            {idx < STAGE_NAMES.length - 1 && (
              <div className={connectorClass(idx)} />
            )}
          </div>
        );
      })}
    </div>
  );
}
