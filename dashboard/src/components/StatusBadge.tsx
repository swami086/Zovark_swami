import '../styles/design-system.css';

type BadgeStatus =
  | 'true_positive'
  | 'suspicious'
  | 'benign'
  | 'needs_review'
  | 'needs_analyst_review'
  | 'error'
  | 'failed'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'pending'
  | 'executing'
  | 'completed';

interface StatusBadgeProps {
  status: BadgeStatus | string;
  className?: string;
}

export default function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const normalized = status.toLowerCase().replace(/\s+/g, '_');

  // Map to CSS class — falls back to badge-pending for unknown statuses
  const badgeClass = [
    'true_positive', 'suspicious', 'benign',
    'needs_review', 'needs_analyst_review',
    'error', 'failed',
    'critical', 'high', 'medium', 'low',
    'pending', 'executing', 'completed',
  ].includes(normalized) ? `badge-${normalized}` : 'badge-pending';

  // Display label: replace underscores with spaces
  const displayLabel = status.replace(/_/g, ' ');

  return (
    <span className={`badge ${badgeClass} ${className}`}>
      {displayLabel}
    </span>
  );
}
