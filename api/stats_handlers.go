package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func getStatsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var totalTasks, completed, failed, pending, executing, inTokens, outTokens int

	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*) as total_tasks,
			COALESCE(COUNT(*) FILTER (WHERE status = 'completed'), 0) as completed,
			COALESCE(COUNT(*) FILTER (WHERE status = 'failed'), 0) as failed,
			COALESCE(COUNT(*) FILTER (WHERE status = 'pending'), 0) as pending,
			COALESCE(COUNT(*) FILTER (WHERE status = 'executing'), 0) as executing,
			COALESCE(SUM(tokens_used_input), 0) as total_tokens_input,
			COALESCE(SUM(tokens_used_output), 0) as total_tokens_output
		FROM agent_tasks WHERE tenant_id = $1
	`, tenantID).Scan(&totalTasks, &completed, &failed, &pending, &executing, &inTokens, &outTokens)

	if err != nil {
		respondInternalError(c, err, "calculate task stats")
		return
	}

	// Task type distribution
	typeRows, _ := dbPool.Query(c.Request.Context(),
		"SELECT COALESCE(task_type, 'unknown'), COUNT(*) FROM agent_tasks WHERE tenant_id = $1 GROUP BY task_type", tenantID)
	typeDistribution := map[string]int{}
	if typeRows != nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var tt string
			var cnt int
			typeRows.Scan(&tt, &cnt)
			typeDistribution[tt] = cnt
		}
	}

	// SIEM alert stats
	var siemTotal, siemNew, siemInvestigating int
	_ = dbPool.QueryRow(c.Request.Context(), `
		SELECT
			COALESCE(COUNT(*), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'new'), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'investigating'), 0)
		FROM siem_alerts WHERE tenant_id = $1
	`, tenantID).Scan(&siemTotal, &siemNew, &siemInvestigating)

	// Recent activity
	actRows, _ := dbPool.Query(c.Request.Context(),
		"SELECT id, status, COALESCE(task_type, 'unknown'), created_at, input->>'prompt' FROM agent_tasks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 10", tenantID)
	var recentActivity []map[string]interface{}
	if actRows != nil {
		defer actRows.Close()
		for actRows.Next() {
			var id, status, tt string
			var createdAt time.Time
			var prompt *string
			actRows.Scan(&id, &status, &tt, &createdAt, &prompt)
			recentActivity = append(recentActivity, map[string]interface{}{
				"id": id, "status": status, "task_type": tt, "created_at": createdAt, "prompt": prompt,
			})
		}
	}
	if recentActivity == nil {
		recentActivity = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_tasks":               totalTasks,
		"completed":                 completed,
		"failed":                    failed,
		"pending":                   pending,
		"executing":                 executing,
		"total_tokens_input":        inTokens,
		"total_tokens_output":       outTokens,
		"type_distribution":         typeDistribution,
		"siem_alerts_total":         siemTotal,
		"siem_alerts_new":           siemNew,
		"siem_alerts_investigating": siemInvestigating,
		"recent_activity":           recentActivity,
	})
}

