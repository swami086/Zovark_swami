package main

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/response/playbooks
// List response playbooks for the requesting tenant (includes global playbooks).
func listResponsePlaybooksHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, name, description, trigger_conditions, actions,
		       requires_approval, enabled, tenant_id, created_at, updated_at
		FROM response_playbooks
		WHERE tenant_id = $1 OR tenant_id IS NULL
		ORDER BY tenant_id NULLS LAST, created_at DESC
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "list response playbooks")
		return
	}
	defer rows.Close()

	var playbooks []map[string]interface{}
	for rows.Next() {
		var id, name string
		var description *string
		var triggerConditions, actions json.RawMessage
		var requiresApproval, enabled bool
		var pbTenantID *string
		var createdAt, updatedAt interface{}

		if err := rows.Scan(&id, &name, &description, &triggerConditions, &actions,
			&requiresApproval, &enabled, &pbTenantID, &createdAt, &updatedAt); err != nil {
			respondInternalError(c, err, "scan response playbook")
			return
		}

		pb := map[string]interface{}{
			"id":                 id,
			"name":               name,
			"description":        description,
			"trigger_conditions": json.RawMessage(triggerConditions),
			"actions":            json.RawMessage(actions),
			"requires_approval":  requiresApproval,
			"enabled":            enabled,
			"tenant_id":          pbTenantID,
			"created_at":         createdAt,
			"updated_at":         updatedAt,
		}
		playbooks = append(playbooks, pb)
	}

	if playbooks == nil {
		playbooks = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"playbooks": playbooks,
		"count":     len(playbooks),
	})
}

// POST /api/v1/response/playbooks
// Create a new response playbook for the tenant.
func createResponsePlaybookHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var req struct {
		Name              string          `json:"name" binding:"required"`
		Description       string          `json:"description"`
		TriggerConditions json.RawMessage `json:"trigger_conditions" binding:"required"`
		Actions           json.RawMessage `json:"actions" binding:"required"`
		RequiresApproval  *bool           `json:"requires_approval"`
		Enabled           *bool           `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	requiresApproval := true
	if req.RequiresApproval != nil {
		requiresApproval = *req.RequiresApproval
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var id string
	err := dbPool.QueryRow(c.Request.Context(), `
		INSERT INTO response_playbooks
		(name, description, trigger_conditions, actions, requires_approval, enabled, tenant_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, req.Name, req.Description, req.TriggerConditions, req.Actions,
		requiresApproval, enabled, tenantID,
	).Scan(&id)

	if err != nil {
		respondInternalError(c, err, "create response playbook")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "playbook created"})
}

// PUT /api/v1/response/playbooks/:id
// Update a response playbook (only tenant-owned, not global).
func updateResponsePlaybookHandler(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	var req struct {
		Name              string          `json:"name"`
		Description       string          `json:"description"`
		TriggerConditions json.RawMessage `json:"trigger_conditions"`
		Actions           json.RawMessage `json:"actions"`
		RequiresApproval  *bool           `json:"requires_approval"`
		Enabled           *bool           `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := dbPool.Exec(c.Request.Context(), `
		UPDATE response_playbooks SET
			name = COALESCE(NULLIF($1, ''), name),
			description = COALESCE(NULLIF($2, ''), description),
			trigger_conditions = COALESCE($3::jsonb, trigger_conditions),
			actions = COALESCE($4::jsonb, actions),
			requires_approval = COALESCE($5, requires_approval),
			enabled = COALESCE($6, enabled),
			updated_at = NOW()
		WHERE id = $7 AND tenant_id = $8
	`, req.Name, req.Description, req.TriggerConditions, req.Actions,
		req.RequiresApproval, req.Enabled, id, tenantID)

	if err != nil {
		respondInternalError(c, err, "update response playbook")
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found or cannot be edited (global playbooks are read-only)"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "playbook updated"})
}

// DELETE /api/v1/response/playbooks/:id
// Disable a response playbook (soft delete, only tenant-owned).
func deleteResponsePlaybookHandler(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	result, err := dbPool.Exec(c.Request.Context(),
		"UPDATE response_playbooks SET enabled = false, updated_at = NOW() WHERE id = $1 AND tenant_id = $2",
		id, tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "disable response playbook")
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found or cannot be disabled"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "playbook disabled"})
}

// GET /api/v1/response/executions
// List response executions for the requesting tenant.
func listResponseExecutionsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	status := c.Query("status")

	query := `
		SELECT re.id, re.playbook_id, rp.name as playbook_name,
		       re.investigation_id, re.status, re.actions_executed,
		       re.approved_by, re.approved_at, re.completed_at,
		       re.error_message, re.created_at
		FROM response_executions re
		JOIN response_playbooks rp ON rp.id = re.playbook_id
		WHERE re.tenant_id = $1
	`
	args := []interface{}{tenantID}

	if status != "" {
		query += " AND re.status = $2"
		args = append(args, status)
	}

	query += " ORDER BY re.created_at DESC LIMIT 100"

	rows, err := dbPool.Query(c.Request.Context(), query, args...)
	if err != nil {
		respondInternalError(c, err, "list response executions")
		return
	}
	defer rows.Close()

	var executions []map[string]interface{}
	for rows.Next() {
		var id, playbookID, playbookName, execStatus string
		var investigationID *string
		var actionsExecuted json.RawMessage
		var approvedBy *string
		var approvedAt, completedAt, createdAt interface{}
		var errorMessage *string

		if err := rows.Scan(&id, &playbookID, &playbookName, &investigationID,
			&execStatus, &actionsExecuted, &approvedBy, &approvedAt,
			&completedAt, &errorMessage, &createdAt); err != nil {
			respondInternalError(c, err, "scan response execution")
			return
		}

		exec := map[string]interface{}{
			"id":               id,
			"playbook_id":      playbookID,
			"playbook_name":    playbookName,
			"investigation_id": investigationID,
			"status":           execStatus,
			"actions_executed": json.RawMessage(actionsExecuted),
			"approved_by":      approvedBy,
			"approved_at":      approvedAt,
			"completed_at":     completedAt,
			"error_message":    errorMessage,
			"created_at":       createdAt,
		}
		executions = append(executions, exec)
	}

	if executions == nil {
		executions = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"executions": executions,
		"count":      len(executions),
	})
}

// GET /api/v1/response/executions/:id
// Get execution details with full action log.
func getResponseExecutionHandler(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	var execID, playbookID, playbookName, execStatus string
	var investigationID *string
	var actionsExecuted, triggerData json.RawMessage
	var approvedBy *string
	var approvedAt, completedAt, createdAt interface{}
	var errorMessage *string

	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT re.id, re.playbook_id, rp.name as playbook_name,
		       re.investigation_id, re.status, re.actions_executed,
		       re.trigger_data, re.approved_by, re.approved_at,
		       re.completed_at, re.error_message, re.created_at
		FROM response_executions re
		JOIN response_playbooks rp ON rp.id = re.playbook_id
		WHERE re.id = $1 AND re.tenant_id = $2
	`, id, tenantID).Scan(&execID, &playbookID, &playbookName, &investigationID,
		&execStatus, &actionsExecuted, &triggerData, &approvedBy,
		&approvedAt, &completedAt, &errorMessage, &createdAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":               execID,
		"playbook_id":      playbookID,
		"playbook_name":    playbookName,
		"investigation_id": investigationID,
		"status":           execStatus,
		"actions_executed": json.RawMessage(actionsExecuted),
		"trigger_data":     json.RawMessage(triggerData),
		"approved_by":      approvedBy,
		"approved_at":      approvedAt,
		"completed_at":     completedAt,
		"error_message":    errorMessage,
		"created_at":       createdAt,
	})
}

// POST /api/v1/response/executions/:id/approve
// Approve a pending response execution.
func approveResponseExecutionHandler(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	result, err := dbPool.Exec(c.Request.Context(), `
		UPDATE response_executions
		SET status = 'executing', approved_by = $1, approved_at = NOW()
		WHERE id = $2 AND tenant_id = $3 AND status = 'awaiting_approval'
	`, userID, id, tenantID)

	if err != nil {
		respondInternalError(c, err, "approve response execution")
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found or not awaiting approval"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "execution approved"})
}

// POST /api/v1/response/executions/:id/rollback
// Rollback a completed response execution.
func rollbackResponseExecutionHandler(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	result, err := dbPool.Exec(c.Request.Context(), `
		UPDATE response_executions
		SET status = 'rolled_back', completed_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND status = 'completed'
	`, id, tenantID)

	if err != nil {
		respondInternalError(c, err, "rollback response execution")
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "execution not found or not in completed state"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "execution rolled back"})
}
