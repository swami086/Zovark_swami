import {
  context,
  diag,
  DiagConsoleLogger,
  DiagLogLevel,
  SpanStatusCode,
  trace,
} from '@opentelemetry/api'
import { logs, SeverityNumber } from '@opentelemetry/api-logs'
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http'
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http'
import { registerInstrumentations } from '@opentelemetry/instrumentation'
import { FetchInstrumentation } from '@opentelemetry/instrumentation-fetch'
import { Resource } from '@opentelemetry/resources'
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from '@opentelemetry/semantic-conventions'
import { BatchLogRecordProcessor, LoggerProvider } from '@opentelemetry/sdk-logs'
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base'
import { WebTracerProvider } from '@opentelemetry/sdk-trace-web'

const TRACER_NAME = 'zovark-dashboard'
const TRACER_VERSION = '3.2.1'

let webLoggerProvider: LoggerProvider | undefined

const otelEnabled = (): boolean => {
  const v = import.meta.env.VITE_OTEL_ENABLED
  if (v == null || v === '') return false
  const s = String(v).toLowerCase().trim()
  return s === '1' || s === 'true' || s === 'yes'
}

function tracesBaseUrl(): string {
  return (
    import.meta.env.VITE_OTEL_EXPORTER_OTLP_TRACES_URL ||
    `${window.location.origin}/otel/v1/traces`
  )
}

function logsBaseUrl(): string {
  if (import.meta.env.VITE_OTEL_EXPORTER_OTLP_LOGS_URL) {
    return import.meta.env.VITE_OTEL_EXPORTER_OTLP_LOGS_URL
  }
  return tracesBaseUrl().replace(/\/v1\/traces\/?$/, '/v1/logs')
}

function installGlobalErrorLoggers(): void {
  const browserLogger = logs.getLogger('zovark-dashboard.browser', TRACER_VERSION)

  const prevOnError = window.onerror
  window.onerror = (message, source, lineno, colno, err) => {
    try {
      browserLogger.emit({
        severityNumber: SeverityNumber.ERROR,
        severityText: 'ERROR',
        body: typeof message === 'string' ? message : 'window.onerror',
        attributes: {
          'event.name': 'browser.window_error',
          'exception.source': source ?? '',
          'exception.lineno': lineno ?? 0,
          'exception.colno': colno ?? 0,
          'exception.message': err?.message ?? String(message),
          'exception.stacktrace': err?.stack ?? '',
        },
      })
    } catch {
      /* ignore telemetry failures */
    }
    if (typeof prevOnError === 'function') {
      return prevOnError.call(window, message, source, lineno, colno, err)
    }
    return false
  }

  window.addEventListener('unhandledrejection', (ev) => {
    try {
      const reason = ev.reason
      const msg =
        reason instanceof Error
          ? reason.message
          : typeof reason === 'string'
            ? reason
            : 'unhandledrejection'
      const stack = reason instanceof Error ? reason.stack ?? '' : ''
      browserLogger.emit({
        severityNumber: SeverityNumber.ERROR,
        severityText: 'ERROR',
        body: msg,
        attributes: {
          'event.name': 'browser.unhandled_rejection',
          'exception.stacktrace': stack,
        },
      })
    } catch {
      /* ignore */
    }
  })
}

/**
 * Browser RUM traces + logs → OTLP HTTP (Ticket 10).
 * Docker: nginx proxies /otel/* to collector. Dev: Vite rewrites /otel → :4318.
 */
export function initBrowserTelemetry(): void {
  if (!otelEnabled()) return

  if (import.meta.env.DEV) {
    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.WARN)
  }

  const traceUrl = tracesBaseUrl()
  const logUrl = logsBaseUrl()

  const resource = new Resource({
    [ATTR_SERVICE_NAME]: 'zovark-dashboard',
    [ATTR_SERVICE_VERSION]: TRACER_VERSION,
  })

  const traceExporter = new OTLPTraceExporter({ url: traceUrl })
  const traceProvider = new WebTracerProvider({ resource })
  traceProvider.addSpanProcessor(new BatchSpanProcessor(traceExporter))
  traceProvider.register()

  const logExporter = new OTLPLogExporter({ url: logUrl })
  webLoggerProvider = new LoggerProvider({ resource, mergeResourceWithDefaults: true })
  webLoggerProvider.addLogRecordProcessor(new BatchLogRecordProcessor(logExporter))
  logs.setGlobalLoggerProvider(webLoggerProvider)

  installGlobalErrorLoggers()

  registerInstrumentations({
    instrumentations: [
      new FetchInstrumentation({
        clearTimingResources: true,
        propagateTraceHeaderCorsUrls: [
          /\/api\//,
          new RegExp(
            `^${window.location.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/api/`,
          ),
        ],
      }),
    ],
  })
}

export function getDashboardTracer() {
  return trace.getTracer(TRACER_NAME, TRACER_VERSION)
}

/** Semantic navigation span (route changes). */
export function recordNavigationPageView(pathname: string): void {
  if (!otelEnabled()) return
  const tracer = getDashboardTracer()
  const span = tracer.startSpan('navigation.page_view')
  span.setAttribute('navigation.path', pathname)
  span.end()
}

export function emitBrowserLog(
  body: string,
  attrs: Record<string, string | number | boolean> = {},
  severity: SeverityNumber = SeverityNumber.INFO,
): void {
  if (!otelEnabled()) return
  const logger = logs.getLogger('zovark-dashboard', TRACER_VERSION)
  const attributes: Record<string, string | number | boolean> = { ...attrs }
  logger.emit({
    severityNumber: severity,
    severityText:
      severity >= SeverityNumber.ERROR
        ? 'ERROR'
        : severity >= SeverityNumber.WARN
          ? 'WARN'
          : 'INFO',
    body,
    attributes,
  })
}

export function emitReactErrorLog(message: string, componentStack: string, stack?: string): void {
  emitBrowserLog(
    message,
    {
      'event.name': 'react.error_boundary',
      'exception.component_stack': componentStack.slice(0, 8000),
      'exception.stacktrace': (stack ?? '').slice(0, 8000),
    },
    SeverityNumber.ERROR,
  )
}

/** Run work inside an active span (manual UI spans). */
export function runInSpan<T>(
  name: string,
  fn: () => T,
  attributes?: Record<string, string | number | boolean>,
): T {
  if (!otelEnabled()) {
    return fn()
  }
  const span = getDashboardTracer().startSpan(name)
  if (attributes) {
    for (const [k, v] of Object.entries(attributes)) {
      span.setAttribute(k, v)
    }
  }
  const ctx = trace.setSpan(context.active(), span)
  try {
    return context.with(ctx, fn)
  } catch (e) {
    span.recordException(e as Error)
    span.setStatus({ code: SpanStatusCode.ERROR, message: (e as Error)?.message })
    throw e
  } finally {
    span.end()
  }
}
