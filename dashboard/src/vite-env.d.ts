/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_OTEL_ENABLED?: string
  readonly VITE_OTEL_EXPORTER_OTLP_TRACES_URL?: string
  readonly VITE_OTEL_EXPORTER_OTLP_LOGS_URL?: string
  readonly VITE_SIGNOZ_UI_BASE?: string
  readonly VITE_API_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
