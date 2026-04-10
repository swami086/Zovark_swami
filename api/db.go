package main

import (
	"context"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

func initDB(dbURL string) error {
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	if otelTracerProvider != nil {
		opts := []otelpgx.Option{otelpgx.WithTracerProvider(otelTracerProvider)}
		if otelMeterProvider != nil {
			opts = append(opts, otelpgx.WithMeterProvider(otelMeterProvider))
		}
		cfg.ConnConfig.Tracer = otelpgx.NewTracer(opts...)
	}
	dbPool, err = pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return err
	}
	if err := dbPool.Ping(context.Background()); err != nil {
		return err
	}
	return nil
}

func closeDB() {
	if dbPool != nil {
		dbPool.Close()
	}
}

// beginTenantTx starts a transaction with RLS tenant context set.
// The caller MUST call tx.Commit() or tx.Rollback() when done.
func beginTenantTx(ctx context.Context, tenantID string) (pgx.Tx, error) {
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tenant tx: %w", err)
	}
	// Use fmt.Sprintf instead of parameterized query because SET LOCAL
	// doesn't support $1 params through PgBouncer transaction pooling.
	// tenantID is a UUID from JWT claims, not user input — safe to inline.
	_, err = tx.Exec(ctx, fmt.Sprintf("SET LOCAL app.current_tenant = '%s'", tenantID))
	if err != nil {
		tx.Rollback(ctx)
		return nil, fmt.Errorf("set tenant context: %w", err)
	}
	return tx, nil
}
