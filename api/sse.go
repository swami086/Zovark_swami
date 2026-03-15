package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// SERVER-SENT EVENTS FOR REAL-TIME UPDATES (Issue #19)
// ============================================================

// taskSSEHandler streams task status updates via Server-Sent Events.
// GET /api/v1/tasks/:id/stream
func taskSSEHandler(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	// Verify task exists and belongs to tenant
	var exists bool
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM agent_tasks WHERE id = $1 AND tenant_id = $2)", taskID, tenantID,
	).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	// Set SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Transfer-Encoding", "chunked")
	c.Header("X-Accel-Buffering", "no") // Disable nginx buffering

	// Track previous state
	var lastStatus string
	var lastStepCount int

	// Send initial connection event
	c.Writer.WriteString("event: connected\n")
	c.Writer.WriteString(fmt.Sprintf("data: {\"task_id\":\"%s\",\"message\":\"SSE stream connected\"}\n\n", taskID))
	c.Writer.Flush()

	// Poll every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Listen for client disconnect
	ctx := c.Request.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Query current task status
			var status string
			var completedAt *time.Time
			var executionMs *int
			var output *string

			err := dbPool.QueryRow(ctx,
				`SELECT status, completed_at, execution_ms, output::text
				 FROM agent_tasks WHERE id = $1 AND tenant_id = $2`,
				taskID, tenantID,
			).Scan(&status, &completedAt, &executionMs, &output)
			if err != nil {
				log.Printf("SSE: error querying task %s: %v", taskID, err)
				continue
			}

			// Check for status change
			if status != lastStatus {
				c.Writer.WriteString("event: status_changed\n")
				dataBytes, _ := json.Marshal(map[string]string{"task_id": taskID, "status": status, "previous_status": lastStatus})
				data := string(dataBytes)
				c.Writer.WriteString(fmt.Sprintf("data: %s\n\n", data))
				c.Writer.Flush()
				lastStatus = status
			}

			// Check for new steps
			var stepCount int
			_ = dbPool.QueryRow(ctx,
				"SELECT COUNT(*) FROM investigation_steps WHERE task_id = $1 AND tenant_id = $2", taskID, tenantID,
			).Scan(&stepCount)

			if stepCount > lastStepCount {
				// Get the latest step info
				var stepNum int
				var stepType, stepStatus string
				var stepOutput *string
				_ = dbPool.QueryRow(ctx,
					`SELECT step_number, step_type, status, output
					 FROM investigation_steps WHERE task_id = $1 AND tenant_id = $2
					 ORDER BY step_number DESC LIMIT 1`, taskID, tenantID,
				).Scan(&stepNum, &stepType, &stepStatus, &stepOutput)

				c.Writer.WriteString("event: step_completed\n")
				outputSnippet := ""
				if stepOutput != nil {
					outputSnippet = *stepOutput
					if len(outputSnippet) > 500 {
						outputSnippet = outputSnippet[:500] + "..."
					}
				}
				stepBytes, _ := json.Marshal(map[string]interface{}{"task_id": taskID, "step_number": stepNum, "step_type": stepType, "status": stepStatus, "output": outputSnippet})
				c.Writer.WriteString(fmt.Sprintf("data: %s\n\n", string(stepBytes)))
				c.Writer.Flush()
				lastStepCount = stepCount
			}

			// If investigation is complete, send final event and close
			if status == "completed" || status == "failed" || status == "cancelled" {
				c.Writer.WriteString("event: investigation_complete\n")
				ms := 0
				if executionMs != nil {
					ms = *executionMs
				}
				completeBytes, _ := json.Marshal(map[string]interface{}{"task_id": taskID, "status": status, "execution_ms": ms, "step_count": stepCount})
				c.Writer.WriteString(fmt.Sprintf("data: %s\n\n", string(completeBytes)))
				c.Writer.Flush()
				return
			}
		}
	}
}
