import '../styles/design-system.css';

interface MetricCardProps {
  value: string | number;
  label: string;
  variant?: 'default' | 'success' | 'danger' | 'warning';
}

const variantColors: Record<string, string> = {
  default: 'var(--text-primary)',
  success: 'var(--accent-green)',
  danger: 'var(--accent-red)',
  warning: 'var(--accent-amber)',
};

const variantGlow: Record<string, string | undefined> = {
  success: 'var(--glow-green)',
};

export default function MetricCard({ value, label, variant = 'default' }: MetricCardProps) {
  return (
    <div
      className="card-surface p-5"
      style={{
        boxShadow: variantGlow[variant] || 'none',
      }}
    >
      <div
        className="metric-number"
        style={{ color: variantColors[variant] }}
      >
        {value}
      </div>
      <div className="metric-label mt-2">
        {label}
      </div>
    </div>
  );
}
