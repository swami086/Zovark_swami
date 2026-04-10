package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DuckDB + postgres_scanner for dashboard aggregations (Ticket 2).

func duckdbExecutable() string {
	if b := os.Getenv("ZOVARK_DUCKDB_BIN"); b != "" {
		return b
	}
	return "duckdb"
}

func escapeSQLString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func duckdbMetricsNamedRow(ctx context.Context, tenantID, selectSQL string) (map[string]interface{}, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL not set")
	}
	replaced := strings.ReplaceAll(selectSQL, "$TENANT", "'"+escapeSQLString(tenantID)+"'")
	script := "INSTALL postgres_scanner; LOAD postgres_scanner; CALL postgres_attach('" +
		escapeSQLString(dsn) + "'); " + replaced
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, duckdbExecutable(), ":memory:", "-json", "-c", script)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("duckdb: %w", err)
	}
	var parsed []map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("duckdb json: %w", err)
	}
	if len(parsed) == 0 {
		return map[string]interface{}{}, nil
	}
	return parsed[0], nil
}

func numF64(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return x
	case json.Number:
		f, _ := x.Float64()
		return f
	default:
		return 0
	}
}

func numI64(m map[string]interface{}, key string) int64 {
	return int64(numF64(m, key))
}
