package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func getPendingApprovalsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT a.id, a.task_id, a.step_number, a.requested_at, a.status, a.risk_level, a.action_summary, a.generated_code,
		       t.task_type, t.input, t.severity
		FROM approval_requests a
		JOIN agent_tasks t ON a.task_id = t.id
		WHERE t.tenant_id = $1 AND a.status = 'pending'
		ORDER BY a.requested_at DESC
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query pending approvals")
		return
	}
	defer rows.Close()

	var approvals []map[string]interface{}
	for rows.Next() {
		var approvalID, taskID, approvalStatus, riskLevel, actionSummary, generatedCode, taskType string
		var stepNumber int
		var requestedAt time.Time
		var taskInput map[string]interface{}
		var severity *string

		if err := rows.Scan(&approvalID, &taskID, &stepNumber, &requestedAt, &approvalStatus, &riskLevel, &actionSummary, &generatedCode, &taskType, &taskInput, &severity); err != nil {
			log.Printf("Error scanning approval row: %v", err)
			continue
		}

		approval := map[string]interface{}{
			"id":             approvalID,
			"task_id":        taskID,
			"step_number":    stepNumber,
			"requested_at":   requestedAt,
			"status":         approvalStatus,
			"risk_level":     riskLevel,
			"action_summary": actionSummary,
			"generated_code": generatedCode,
			"task_type":      taskType,
			"prompt":         taskInput["prompt"],
			"severity":       severity,
		}
		approvals = append(approvals, approval)
	}

	if approvals == nil {
		approvals = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"approvals": approvals, "count": len(approvals)})
}

func decideApprovalHandler(c *gin.Context) {
	approvalID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Approved bool   `json:"approved"`
		Comment  string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the approval belongs to this tenant and is pending
	var taskID string
	var approvalStatus string
	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT a.task_id, a.status
		FROM approval_requests a
		JOIN agent_tasks t ON a.task_id = t.id
		WHERE a.id = $1 AND t.tenant_id = $2
	`, approvalID, tenantID).Scan(&taskID, &approvalStatus)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found"})
		return
	}

	if approvalStatus != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approval already decided"})
		return
	}

	// Update the approval request
	decisionStatus := "rejected"
	if req.Approved {
		decisionStatus = "approved"
	}
	_, err = dbPool.Exec(c.Request.Context(),
		"UPDATE approval_requests SET status = $1, decided_at = NOW(), decided_by = $2, decision_comment = $3 WHERE id = $4",
		decisionStatus, userID, req.Comment, approvalID,
	)
	if err != nil {
		respondInternalError(c, err, "update approval record")
		return
	}

	// Send Temporal signal to the waiting workflow
	workflowID := "task-" + taskID
	signalPayload := map[string]interface{}{
		"approved":   req.Approved,
		"comment":    req.Comment,
		"decided_by": userID,
	}

	err = tc.SignalWorkflow(context.Background(), workflowID, "", "approval_decision", signalPayload)
	if err != nil {
		respondInternalError(c, err, "signal approval workflow")
		return
	}

	// Audit log
	action := "approval_approved"
	if !req.Approved {
		action = "approval_rejected"
	}
	_, _ = dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, action, "task", taskID, func() string { d, _ := json.Marshal(map[string]string{"approval_id": approvalID, "comment": req.Comment}); return string(d) }(),
	)

	c.JSON(http.StatusOK, gin.H{
		"status":      decisionStatus,
		"approval_id": approvalID,
		"task_id":     taskID,
	})
}
