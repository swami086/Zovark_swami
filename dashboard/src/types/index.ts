export interface WorkflowStep {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  input?: Record<string, unknown>;
  output?: Record<string, unknown>;
  error?: string;
  guardrail_score?: number;
  guardrail_threshold?: number;
  retry_count?: number;
  model_name?: string;
  execution_context?: 'local' | 'llm';
}

export const STEP_LABELS: Record<string, string> = {
  'parse_alert': 'Parse Alert',
  'generate_python': 'Generate Investigation Code',
  'generate_code': 'Generate Investigation Code',
  'execute_sandbox': 'Execute in Sandbox',
  'execute_code': 'Execute in Sandbox',
  'extract_entities': 'Extract Entities',
  'guardrail_check': 'Quality Validation',
  'validate_generated_code': 'Quality Validation',
  'generate_report': 'Generate Report',
  'generate_incident_report': 'Generate Report',
  'complete': 'Investigation Complete',
  'analysis': 'Analysis',
  'enrichment': 'Enrichment',
  'deep_analysis': 'Deep Analysis',
};
