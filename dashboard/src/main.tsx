import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { initBrowserTelemetry } from './telemetry'
import { OtelErrorBoundary } from './components/OtelErrorBoundary'
import App from './App.tsx'

initBrowserTelemetry()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <OtelErrorBoundary>
      <App />
    </OtelErrorBoundary>
  </StrictMode>,
)
