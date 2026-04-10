package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/sdk/resource"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

var apiOtelLoggerProvider *sdklog.LoggerProvider

// initAPIOTelLogsWithResource wires structured slog → OTLP logs (SigNoz pipelines.logs) when OTEL_ENABLED.
func initAPIOTelLogsWithResource(ctx context.Context, hostport string, insecure bool, res *resource.Resource) {
	if !apiOtelEnabled() {
		return
	}
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(hostport),
	}
	if insecure {
		opts = append(opts, otlploghttp.WithInsecure())
	}
	exporter, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		log.Printf("[OTEL] API log exporter init failed (logs not exported): %v", err)
		return
	}
	proc := sdklog.NewBatchProcessor(exporter,
		sdklog.WithExportInterval(2*time.Second),
		sdklog.WithExportTimeout(10*time.Second),
	)
	apiOtelLoggerProvider = sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(proc),
	)
	global.SetLoggerProvider(apiOtelLoggerProvider)

	otelH := otelslog.NewHandler("zovark-api",
		otelslog.WithLoggerProvider(apiOtelLoggerProvider),
		otelslog.WithVersion("3.2.1"),
	)
	stdH := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(newTeeSlogHandler(stdH, otelH)))

	log.Printf("[OTEL] API structured logs → OTLP HTTP %s/v1/logs (insecure=%v)", hostport, insecure)
}

func shutdownAPIOTelLogs(ctx context.Context) {
	if apiOtelLoggerProvider == nil {
		return
	}
	if err := apiOtelLoggerProvider.Shutdown(ctx); err != nil {
		log.Printf("[OTEL] API logger provider shutdown: %v", err)
	}
	apiOtelLoggerProvider = nil
}
