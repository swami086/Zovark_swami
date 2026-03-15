package main

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func getMeHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"user": map[string]interface{}{
			"id":        c.GetString("user_id"),
			"role":      c.GetString("user_role"),
			"tenant_id": c.GetString("tenant_id"),
		},
	})
}

func getNotificationsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	sinceStr := c.Query("since")
	var sinceTime time.Time
	if sinceStr != "" {
		parsed, err := time.Parse(time.RFC3339, sinceStr)
		if err == nil {
			sinceTime = parsed
		} else {
			sinceTime = time.Now().Add(-60 * time.Second)
		}
	} else {
		sinceTime = time.Now().Add(-60 * time.Second)
	}

	var notifications []map[string]interface{}

	// Fetch recent audit logs (completions, approvals)
	auditRows, err := dbPool.Query(c.Request.Context(), `
		SELECT action, resource_id, created_at
		FROM agent_audit_log
		WHERE tenant_id = $1 AND created_at > $2 AND action IN ('task_completed', 'approval_requested')
		ORDER BY created_at DESC LIMIT 20
	`, tenantID, sinceTime)

	if err == nil {
		defer auditRows.Close()
		for auditRows.Next() {
			var action, resID string
			var ts time.Time
			auditRows.Scan(&action, &resID, &ts)

			var message string
			if action == "task_completed" {
				message = fmt.Sprintf("Investigation completed: %s", resID[:8])
			} else if action == "approval_requested" {
				message = fmt.Sprintf("Approval required for investigation %s", resID[:8])
			}

			notifications = append(notifications, map[string]interface{}{
				"id":        uuid.New().String(),
				"type":      action,
				"message":   message,
				"task_id":   resID,
				"timestamp": ts,
			})
		}
	}

	// Fetch new SIEM alerts
	alertRows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, title, created_at
		FROM siem_alerts
		WHERE tenant_id = $1 AND created_at > $2 AND status = 'new'
		ORDER BY created_at DESC LIMIT 20
	`, tenantID, sinceTime)

	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var altID, title string
			var ts time.Time
			alertRows.Scan(&altID, &title, &ts)

			notifications = append(notifications, map[string]interface{}{
				"id":        altID,
				"type":      "siem_alert",
				"message":   fmt.Sprintf("New SIEM Alert: %s", title),
				"timestamp": ts,
			})
		}
	}

	if notifications == nil {
		notifications = []map[string]interface{}{}
	} else {
		sort.Slice(notifications, func(i, j int) bool {
			return notifications[i]["timestamp"].(time.Time).After(notifications[j]["timestamp"].(time.Time))
		})
	}

	c.JSON(http.StatusOK, gin.H{"notifications": notifications})
}
