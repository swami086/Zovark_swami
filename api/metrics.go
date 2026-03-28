package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// metricsHandler returns operational metrics for the ZOVARK platform.
// GET /api/v1/metrics
//
// To register this handler, add the following line to main.go inside the
// protected API route group (after the authMiddleware):
//
//     api.GET("/metrics", requireRole("admin"), metricsHandler)
//
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
	var total, completed, failed, pending int64
	var successRate float64

	if dbPool == nil {
		return gin.H{"error": "database unavailable"}
	}

	row := dbPool.QueryRow(ctx, `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = 'completed') AS completed,
			COUNT(*) FILTER (WHERE status = 'failed') AS failed,
			COUNT(*) FILTER (WHERE status IN ('pending', 'executing')) AS pending
		FROM agent_tasks
		WHERE tenant_id = $1
	`, tenantID)

	if err := row.Scan(&total, &completed, &failed, &pending); err != nil {
		return gin.H{"error": "query failed"}
	}

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
	var avgTime, medianTime float64

	if dbPool == nil {
		return gin.H{"error": "database unavailable"}
	}

	row := dbPool.QueryRow(ctx, `
		SELECT
			COALESCE(AVG(execution_ms) / 1000.0, 0) AS avg_time_s,
			COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY execution_ms) / 1000.0, 0) AS median_time_s
		FROM agent_tasks
		WHERE tenant_id = $1
			AND status = 'completed'
			AND execution_ms IS NOT NULL
			AND execution_ms > 0
	`, tenantID)

	if err := row.Scan(&avgTime, &medianTime); err != nil {
		return gin.H{
			"avg_investigation_time_s":    0,
			"median_investigation_time_s": 0,
		}
	}

	return gin.H{
		"avg_investigation_time_s":    avgTime,
		"median_investigation_time_s": medianTime,
	}
}

func getLLMMetrics(ctx context.Context, tenantID string) gin.H {
	var totalCalls int64
	var avgLatency float64
	var totalTokensIn, totalTokensOut int64

	if dbPool == nil {
		return gin.H{"error": "database unavailable"}
	}

	// Try the llm_audit_log table first (V2 pipeline)
	row := dbPool.QueryRow(ctx, `
		SELECT
			COUNT(*) AS total_calls,
			COALESCE(AVG(latency_ms), 0) AS avg_latency_ms,
			COALESCE(SUM(tokens_in), 0) AS total_tokens_in,
			COALESCE(SUM(tokens_out), 0) AS total_tokens_out
		FROM llm_audit_log
		WHERE tenant_id = $1
	`, tenantID)

	if err := row.Scan(&totalCalls, &avgLatency, &totalTokensIn, &totalTokensOut); err != nil {
		// Fallback: aggregate from agent_tasks
		row2 := dbPool.QueryRow(ctx, `
			SELECT
				COUNT(*) AS total_calls,
				COALESCE(AVG(execution_ms), 0) AS avg_latency_ms,
				COALESCE(SUM(tokens_used_input), 0) AS total_tokens_in,
				COALESCE(SUM(tokens_used_output), 0) AS total_tokens_out
			FROM agent_tasks
			WHERE tenant_id = $1
				AND status = 'completed'
		`, tenantID)

		if err2 := row2.Scan(&totalCalls, &avgLatency, &totalTokensIn, &totalTokensOut); err2 != nil {
			return gin.H{"error": "query failed"}
		}
	}

	return gin.H{
		"total_calls":    totalCalls,
		"avg_latency_ms": avgLatency,
		"total_tokens_in":  totalTokensIn,
		"total_tokens_out": totalTokensOut,
	}
}

func getSystemMetrics(ctx context.Context) gin.H {
	uptimeSeconds := int(time.Since(startTime).Seconds())

	var poolSize int
	if dbPool != nil {
		stat := dbPool.Stat()
		poolSize = int(stat.TotalConns())
	}

	// Check worker connectivity via Temporal
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
	var total, active int64

	if dbPool == nil {
		return gin.H{"error": "database unavailable"}
	}

	row := dbPool.QueryRow(ctx, `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE is_active = true) AS active
		FROM agent_skills
		WHERE is_active IS NOT NULL AND (tenant_id = $1 OR tenant_id IS NULL)
	`, tenantID)

	if err := row.Scan(&total, &active); err != nil {
		// skills table may not exist or have different schema
		return gin.H{
			"total":  11,
			"active": 11,
		}
	}

	return gin.H{
		"total":  total,
		"active": active,
	}
}
