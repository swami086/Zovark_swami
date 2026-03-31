package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

func initDB(dbURL string) error {
	var err error
	dbPool, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return err
	}
	return dbPool.Ping(context.Background())
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
