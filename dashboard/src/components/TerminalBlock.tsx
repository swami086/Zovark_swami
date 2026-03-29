import '../styles/design-system.css';

interface TerminalLine {
  text: string;
  color?: string; // CSS color or var()
}

interface TerminalBlockProps {
  title?: string;
  lines?: TerminalLine[];
  children?: React.ReactNode;
  maxHeight?: string;
}

export default function TerminalBlock({ title = 'terminal', lines, children, maxHeight }: TerminalBlockProps) {
  return (
    <div className="terminal-window">
      {/* macOS-style title bar */}
      <div className="terminal-titlebar">
        <div className="terminal-dots">
          <span className="terminal-dot terminal-dot-red" />
          <span className="terminal-dot terminal-dot-amber" />
          <span className="terminal-dot terminal-dot-green" />
        </div>
        <span className="terminal-title">{title}</span>
      </div>

      {/* Body */}
      <div className="terminal-body" style={maxHeight ? { maxHeight } : undefined}>
        {lines ? (
          <pre>
            {lines.map((line, i) => (
              <div key={i} style={{ color: line.color || 'var(--text-secondary)' }}>
                {line.text}
              </div>
            ))}
          </pre>
        ) : (
          children
        )}
      </div>
    </div>
  );
}
