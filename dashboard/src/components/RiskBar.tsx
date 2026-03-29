import '../styles/design-system.css';

interface RiskBarProps {
  value: number; // 0–100
  showLabel?: boolean;
  className?: string;
}

export default function RiskBar({ value, showLabel = true, className = '' }: RiskBarProps) {
  const clamped = Math.max(0, Math.min(100, value));

  let tierClass: string;
  if (clamped <= 35) {
    tierClass = 'risk-bar-low';
  } else if (clamped <= 69) {
    tierClass = 'risk-bar-medium';
  } else {
    tierClass = 'risk-bar-high';
  }

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <div className="risk-bar-track flex-1">
        <div
          className={`risk-bar-fill ${tierClass}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
      {showLabel && (
        <span
          className="label"
          style={{
            color: clamped <= 35
              ? 'var(--text-muted)'
              : clamped <= 69
                ? 'var(--accent-amber)'
                : 'var(--accent-red)',
            minWidth: '28px',
            textAlign: 'right',
          }}
        >
          {clamped}
        </span>
      )}
    </div>
  );
}
