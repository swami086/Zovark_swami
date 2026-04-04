package main

import (
	"context"
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

// streamAllTaskUpdates provides a global SSE stream for all task completions.
// GET /api/v1/tasks/stream
// Supports token as query param since EventSource doesn't support headers.
func streamAllTaskUpdates(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	// Send connected event
	c.Writer.WriteString("event: connected\n")
	c.Writer.WriteString(fmt.Sprintf("data: {\"message\":\"SSE stream connected\",\"tenant\":\"%s\"}\n\n", tenantID[:8]))
	c.Writer.Flush()

	// Try to use PostgreSQL LISTEN/NOTIFY
	conn, err := dbPool.Acquire(c.Request.Context())
	if err != nil {
		log.Printf("SSE: failed to acquire DB connection: %v", err)
		c.Writer.WriteString(fmt.Sprintf("event: error\ndata: {\"error\":\"db connection failed\"}\n\n"))
		c.Writer.Flush()
		return
	}
	defer conn.Release()

	// LISTEN for task completions (NOTIFY sent by store.py)
	_, err = conn.Exec(c.Request.Context(), "LISTEN task_completed")
	if err != nil {
		log.Printf("SSE: LISTEN failed, falling back to polling: %v", err)
		streamAllTasksPolling(c, tenantID)
		return
	}
	// LISTEN for investigation events (NOTIFY sent by events.py — waterfall streaming)
	_, _ = conn.Exec(c.Request.Context(), "LISTEN investigation_events")

	ctx := c.Request.Context()
	// Send a keepalive every 15s to prevent proxy timeouts
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Writer.WriteString(": keepalive\n\n")
			c.Writer.Flush()
		default:
			// Wait for notification with 5s timeout
			notification, err := conn.Conn().WaitForNotification(context.Background())
			if err != nil {
				continue
			}

			// Parse the notification payload
			var payload map[string]interface{}
			if json.Unmarshal([]byte(notification.Payload), &payload) == nil {
				// Filter by tenant_id
				if payloadTenant, ok := payload["tenant_id"].(string); ok && payloadTenant != tenantID {
					continue
				}
				data, _ := json.Marshal(payload)
				// Use event_type from payload if present (waterfall events), else task_completed
				eventType := "task_completed"
				if et, ok := payload["event_type"].(string); ok && et != "" {
					eventType = et
				}
				// Trigger SIEM push-back on task completion
				if eventType == "task_completed" {
					if tid, ok := payload["task_id"].(string); ok {
						ptid := ""
						if pt, ok := payload["tenant_id"].(string); ok {
							ptid = pt
						}
						triggerPushbackFromNotify(tid, ptid)
					}
				}
				c.Writer.WriteString(fmt.Sprintf("event: %s\n", eventType))
				if traceID, ok := payload["trace_id"].(string); ok && traceID != "" {
					c.Writer.WriteString(fmt.Sprintf("id: %s\n", traceID))
				}
				c.Writer.WriteString(fmt.Sprintf("data: %s\n\n", string(data)))
				c.Writer.Flush()
			}
		}
	}
}

// streamAllTasksPolling is a fallback that polls for recently completed tasks.
func streamAllTasksPolling(c *gin.Context, tenantID string) {
	ctx := c.Request.Context()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	lastCheck := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, err := dbPool.Query(ctx, `
				SELECT id, task_type, status, (output->>'verdict')::text, (output->>'risk_score')::int
				FROM agent_tasks
				WHERE tenant_id = $1 AND completed_at > $2
				ORDER BY completed_at DESC LIMIT 10
			`, tenantID, lastCheck)
			if err != nil {
				continue
			}

			for rows.Next() {
				var id, taskType, status string
				var verdict *string
				var riskScore *int
				if err := rows.Scan(&id, &taskType, &status, &verdict, &riskScore); err != nil {
					continue
				}
				evt := map[string]interface{}{
					"task_id":    id,
					"task_type":  taskType,
					"status":     status,
					"verdict":    verdict,
					"risk_score": riskScore,
				}
				data, _ := json.Marshal(evt)
				c.Writer.WriteString("event: task_completed\n")
				c.Writer.WriteString(fmt.Sprintf("data: %s\n\n", string(data)))
				c.Writer.Flush()
			}
			rows.Close()
			lastCheck = time.Now()
		}
	}
}

