package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// metricsHandler returns operational metrics for the ZOVARK platform.
// GET /api/v1/metrics — aggregations read via DuckDB postgres_scanner (Ticket 2).

func metricsHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)

	metrics := gin.H{
		"investigations": getInvestigationMetrics(ctx, tid),
		"performance":    getPerformanceMetrics(ctx, tid),
		"llm":            getLLMMetrics(ctx, tid),
		"system":         getSystemMetrics(ctx),
		"templates":      getTemplateMetrics(ctx, tid),
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"data":   metrics,
	})
}

func getInvestigationMetrics(ctx context.Context, tenantID string) gin.H {
	row, err := duckdbMetricsNamedRow(ctx, tenantID, `
SELECT
  COUNT(*)::DOUBLE AS total,
  COUNT(*) FILTER (WHERE status = 'completed')::DOUBLE AS completed,
  COUNT(*) FILTER (WHERE status = 'failed')::DOUBLE AS failed,
  COUNT(*) FILTER (WHERE status IN ('pending', 'executing'))::DOUBLE AS pending
FROM agent_tasks
WHERE tenant_id = $TENANT::uuid
`)
	if err != nil {
		return gin.H{"error": "duckdb metrics unavailable"}
	}
	total := numI64(row, "total")
	completed := numI64(row, "completed")
	failed := numI64(row, "failed")
	pending := numI64(row, "pending")
	var successRate float64
	if total > 0 {
		successRate = float64(completed) / float64(total) * 100
	}
	return gin.H{
		"total":        total,
		"completed":    completed,
		"failed":       failed,
		"pending":      pending,
		"success_rate": successRate,
	}
}

func getPerformanceMetrics(ctx context.Context, tenantID string) gin.H {
	row, err := duckdbMetricsNamedRow(ctx, tenantID, `
SELECT
  COALESCE(AVG(execution_ms) / 1000.0, 0)::DOUBLE AS avg_time_s,
  COALESCE(median(execution_ms) / 1000.0, 0)::DOUBLE AS median_time_s
FROM agent_tasks
WHERE tenant_id = $TENANT::uuid
  AND status = 'completed'
  AND execution_ms IS NOT NULL
  AND execution_ms > 0
`)
	if err != nil {
		return gin.H{
			"avg_investigation_time_s":    0,
			"median_investigation_time_s": 0,
			"error":                       "duckdb metrics unavailable",
		}
	}
	return gin.H{
		"avg_investigation_time_s":    numF64(row, "avg_time_s"),
		"median_investigation_time_s": numF64(row, "median_time_s"),
	}
}

func getLLMMetrics(ctx context.Context, tenantID string) gin.H {
	row, err := duckdbMetricsNamedRow(ctx, tenantID, `
SELECT
  COUNT(*)::DOUBLE AS total_calls,
  COALESCE(AVG(latency_ms), 0)::DOUBLE AS avg_latency_ms,
  COALESCE(SUM(tokens_in), 0)::DOUBLE AS total_tokens_in,
  COALESCE(SUM(tokens_out), 0)::DOUBLE AS total_tokens_out
FROM llm_audit_log
WHERE tenant_id = $TENANT::uuid
`)
	if err != nil || numI64(row, "total_calls") == 0 {
		row2, err2 := duckdbMetricsNamedRow(ctx, tenantID, `
SELECT
  COUNT(*)::DOUBLE AS total_calls,
  COALESCE(AVG(execution_ms), 0)::DOUBLE AS avg_latency_ms,
  COALESCE(SUM(tokens_used_input), 0)::DOUBLE AS total_tokens_in,
  COALESCE(SUM(tokens_used_output), 0)::DOUBLE AS total_tokens_out
FROM agent_tasks
WHERE tenant_id = $TENANT::uuid
  AND status = 'completed'
`)
		if err2 != nil {
			return gin.H{"error": "duckdb metrics unavailable"}
		}
		row = row2
	}
	return gin.H{
		"total_calls":      numI64(row, "total_calls"),
		"avg_latency_ms":   numF64(row, "avg_latency_ms"),
		"total_tokens_in":  numI64(row, "total_tokens_in"),
		"total_tokens_out": numI64(row, "total_tokens_out"),
	}
}

func getSystemMetrics(ctx context.Context) gin.H {
	uptimeSeconds := int(time.Since(startTime).Seconds())

	var poolSize int
	if dbPool != nil {
		stat := dbPool.Stat()
		poolSize = int(stat.TotalConns())
	}

	workerStatus := "unknown"
	if tc != nil {
		workerStatus = "connected"
	}

	return gin.H{
		"uptime_s":                uptimeSeconds,
		"db_connection_pool_size": poolSize,
		"worker_status":           workerStatus,
	}
}

func getTemplateMetrics(ctx context.Context, tenantID string) gin.H {
	row, err := duckdbMetricsNamedRow(ctx, tenantID, `
SELECT
  COUNT(*)::DOUBLE AS total,
  COUNT(*) FILTER (WHERE is_active = true)::DOUBLE AS active
FROM agent_skills
WHERE is_active IS NOT NULL AND (tenant_id = $TENANT::uuid OR tenant_id IS NULL)
`)
	if err != nil {
		return gin.H{"total": 11, "active": 11, "error": "duckdb metrics unavailable"}
	}
	return gin.H{
		"total":  numI64(row, "total"),
		"active": numI64(row, "active"),
	}
}
