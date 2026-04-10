package main

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	apiInstrOnce         sync.Once
	apiRequestsCounter   metric.Int64Counter
	apiRequestDuration   metric.Float64Histogram
	apiIngestCounter     metric.Int64Counter
	apiDedupCounter      metric.Int64Counter
	apiInstrumentsReady  bool
)

func initAPIInstruments() {
	if !apiOtelEnabled() || otelMeterProvider == nil {
		return
	}
	apiInstrOnce.Do(func() {
		m := otel.Meter("zovark-api")
		var err error
		apiRequestsCounter, err = m.Int64Counter("zovark_api_requests_total",
			metric.WithDescription("Total HTTP requests"))
		if err != nil {
			return
		}
		apiRequestDuration, err = m.Float64Histogram("zovark_api_request_duration_seconds",
			metric.WithDescription("Request duration in seconds"))
		if err != nil {
			return
		}
		apiIngestCounter, err = m.Int64Counter("zovark_api_ingest_events_total",
			metric.WithDescription("SIEM ingest events accepted"))
		if err != nil {
			return
		}
		apiDedupCounter, err = m.Int64Counter("zovark_api_dedup_hits_total",
			metric.WithDescription("Pre-Temporal dedup suppressions"))
		if err != nil {
			return
		}
		_, err = m.Int64ObservableGauge("zovark_api_db_pool_acquired_connections",
			metric.WithInt64Callback(func(_ context.Context, obs metric.Int64Observer) error {
				if dbPool != nil {
					obs.Observe(int64(dbPool.Stat().AcquiredConns()))
				}
				return nil
			}),
			metric.WithDescription("DB pool acquired connections"),
		)
		if err != nil {
			return
		}
		apiInstrumentsReady = true
	})
}

func recordAPIRequest(ctx context.Context, method, route string, status int, durationSec float64) {
	if !apiInstrumentsReady {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("http.method", method),
		attribute.String("http.route", route),
		attribute.Int("http.status_code", status),
	}
	apiRequestsCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	apiRequestDuration.Record(ctx, durationSec, metric.WithAttributes(attrs...))
}

func recordAPIIngest(ctx context.Context, source string) {
	if !apiInstrumentsReady {
		return
	}
	apiIngestCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("source", source)))
}

func recordAPIDedupHit(ctx context.Context) {
	if !apiInstrumentsReady {
		return
	}
	apiDedupCounter.Add(ctx, 1)
}
