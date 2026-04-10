package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

var (
	otelTracerProvider *sdktrace.TracerProvider
	otelMeterProvider  *sdkmetric.MeterProvider
)

func apiOtelEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("OTEL_ENABLED")))
	if v == "" {
		return false
	}
	return v == "1" || v == "true" || v == "yes"
}

func apiOtelEndpointRaw() string {
	if e := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); e != "" {
		return e
	}
	if e := strings.TrimSpace(os.Getenv("ZOVARK_OTEL_ENDPOINT")); e != "" {
		return e
	}
	return "http://zovark-signoz-collector:4318"
}

// zovarkTraceUUIDFromContext maps the active OTel trace ID to a UUID string for
// agent_tasks.trace_id and X-Zovark-Trace-ID (Ticket 7).
func zovarkTraceUUIDFromContext(ctx context.Context) string {
	sc := oteltrace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return uuid.New().String()
	}
	tid := sc.TraceID()
	var raw [16]byte
	copy(raw[:], tid[:])
	u, err := uuid.FromBytes(raw[:])
	if err != nil {
		return uuid.New().String()
	}
	return u.String()
}

// OTLP HTTP host:port for Signoz collector (no path, no scheme in endpoint option).
func parseOTLPHostPort(raw string) (hostport string, insecure bool) {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "/"))
	insecure = true
	if strings.HasPrefix(raw, "https://") {
		insecure = false
		raw = strings.TrimPrefix(raw, "https://")
	} else if strings.HasPrefix(raw, "http://") {
		raw = strings.TrimPrefix(raw, "http://")
	}
	if i := strings.Index(raw, "/"); i >= 0 {
		raw = raw[:i]
	}
	return raw, insecure
}

func initAPIOTel(ctx context.Context) {
	if !apiOtelEnabled() {
		log.Println("[OTEL] API tracing disabled (set OTEL_ENABLED=true and OTLP endpoint to enable)")
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
		return
	}

	hostport, insecure := parseOTLPHostPort(apiOtelEndpointRaw())
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(hostport),
	}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		log.Printf("[OTEL] API exporter init failed (tracing off): %v", err)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
		return
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName("zovark-api"),
			semconv.ServiceVersion("3.2.1"),
		),
	)
	if err != nil {
		res = resource.Default()
	}

	otelTracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithMaxExportBatchSize(512),
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(otelTracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	log.Printf("[OTEL] API tracing enabled → OTLP HTTP %s (insecure=%v)", hostport, insecure)

	mopts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(hostport),
	}
	if insecure {
		mopts = append(mopts, otlpmetrichttp.WithInsecure())
	}
	mexp, mErr := otlpmetrichttp.New(ctx, mopts...)
	if mErr != nil {
		log.Printf("[OTEL] API metrics exporter failed (metrics off): %v", mErr)
	} else {
		reader := sdkmetric.NewPeriodicReader(mexp, sdkmetric.WithInterval(10*time.Second))
		otelMeterProvider = sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(reader),
			sdkmetric.WithResource(res),
		)
		otel.SetMeterProvider(otelMeterProvider)
		initAPIInstruments()
		log.Printf("[OTEL] API metrics enabled → OTLP HTTP %s/v1/metrics", hostport)
	}
}

func shutdownAPIOTel(ctx context.Context) {
	if otelMeterProvider != nil {
		if err := otelMeterProvider.Shutdown(ctx); err != nil {
			log.Printf("[OTEL] API meter shutdown: %v", err)
		}
		otelMeterProvider = nil
	}
	if otelTracerProvider == nil {
		return
	}
	if err := otelTracerProvider.Shutdown(ctx); err != nil {
		log.Printf("[OTEL] API tracer shutdown: %v", err)
	}
	otelTracerProvider = nil
}

// injectOTelTraceContext adds W3C traceparent/tracestate to the Redpanda task envelope
// so the worker can continue the same trace in SigNoz (Ticket 7).
func injectOTelTraceContext(ctx context.Context, payload map[string]interface{}) {
	carrier := make(propagation.MapCarrier)
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if v := carrier["traceparent"]; v != "" {
		payload["traceparent"] = v
	}
	if v := carrier["tracestate"]; v != "" {
		payload["tracestate"] = v
	}
}

func otelGinMiddleware() gin.HandlerFunc {
	if !apiOtelEnabled() || otelTracerProvider == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return otelgin.Middleware("zovark-api",
		otelgin.WithTracerProvider(otelTracerProvider),
		otelgin.WithFilter(func(r *http.Request) bool {
			// Reduce noise from Docker/k8s probes
			if r.URL.Path == "/health" || r.URL.Path == "/ready" {
				return false
			}
			return true
		}),
	)
}

// zovarkTraceHeaderMiddleware sets X-Zovark-Trace-ID from OTel context on every response (Ticket 7).
func zovarkTraceHeaderMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Zovark-Trace-ID", zovarkTraceUUIDFromContext(c.Request.Context()))
		c.Next()
	}
}

// otelHTTPMetricsMiddleware records request counts and duration histograms.
func otelHTTPMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = c.Request.URL.Path
		}
		recordAPIRequest(c.Request.Context(), c.Request.Method, route, c.Writer.Status(), time.Since(start).Seconds())
	}
}
