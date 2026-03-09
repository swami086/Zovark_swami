import { AlertTriangle } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function DemoBanner() {
  return (
    <div className="sticky top-0 z-50 bg-amber-500/10 border-b border-amber-500/30 py-2 px-6">
      <div className="flex items-center justify-between max-w-[1200px] mx-auto">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span className="text-amber-400 text-sm">
            DEMO MODE &mdash; This is simulated data for demonstration purposes
          </span>
        </div>
        <Link
          to="/tasks"
          className="text-amber-400 text-sm hover:text-amber-300 transition-colors duration-200"
        >
          View Real Investigations &rarr;
        </Link>
      </div>
    </div>
  );
}
