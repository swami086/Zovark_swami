import { Component, type ErrorInfo, type ReactNode } from 'react'
import { emitReactErrorLog } from '../telemetry'

type Props = { children: ReactNode }

type State = { hasError: boolean; message: string }

export class OtelErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, message: '' }

  static getDerivedStateFromError(err: Error): State {
    return { hasError: true, message: err?.message || 'Unexpected error' }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    emitReactErrorLog(error.message, info.componentStack ?? '', error.stack)
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen app-bg app-text flex items-center justify-center p-8">
          <div className="max-w-md rounded-xl border border-rose-500/30 bg-rose-500/10 p-6 text-center space-y-4">
            <h1 className="text-lg font-bold text-rose-300">Something went wrong</h1>
            <p className="text-sm text-slate-400 font-mono break-words">{this.state.message}</p>
            <button
              type="button"
              className="px-4 py-2 rounded-lg bg-slate-800 text-[#00FF88] hover:bg-slate-700"
              onClick={() => window.location.reload()}
            >
              Reload page
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
