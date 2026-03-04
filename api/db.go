package main

import (
	"context"

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
