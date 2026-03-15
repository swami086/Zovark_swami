package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================
// KILL SWITCH / AUTOMATION CONTROLS (Sprint v0.10.0)
// ============================================================

// GET /api/v1/automation/controls — list automation controls for tenant
func listAutomationControlsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, scope, scope_target, mode, enabled, created_at, updated_at, created_by, kill_reason
		FROM automation_controls
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query automation controls")
		return
	}
	defer rows.Close()

	var controls []map[string]interface{}
	for rows.Next() {
		var id, scope, mode string
		var scopeTarget, createdBy, killReason *string
		var enabled bool
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &scope, &scopeTarget, &mode, &enabled, &createdAt, &updatedAt, &createdBy, &killReason); err != nil {
			log.Printf("Error scanning automation control row: %v", err)
			continue
		}

		controls = append(controls, map[string]interface{}{
			"id":           id,
			"scope":        scope,
			"scope_target": scopeTarget,
			"mode":         mode,
			"enabled":      enabled,
			"created_at":   createdAt,
			"updated_at":   updatedAt,
			"created_by":   createdBy,
			"kill_reason":  killReason,
		})
	}

	if controls == nil {
		controls = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"controls": controls, "count": len(controls)})
}

// POST /api/v1/automation/controls — create or update automation control
func upsertAutomationControlHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Scope       string `json:"scope" binding:"required"`
		ScopeTarget string `json:"scope_target"`
		Mode        string `json:"mode" binding:"required"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate scope
	validScopes := map[string]bool{
		"tenant":   true,
		"workflow": true,
		"activity": true,
		"playbook": true,
	}
	if !validScopes[req.Scope] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope; must be tenant, workflow, activity, or playbook"})
		return
	}

	// Validate mode
	validModes := map[string]bool{
		"shadow":     true,
		"assisted":   true,
		"autonomous": true,
		"disabled":   true,
	}
	if !validModes[req.Mode] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mode; must be shadow, assisted, autonomous, or disabled"})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Upsert: check if control exists for this scope+target
	var existingID string
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT id FROM automation_controls WHERE tenant_id = $1 AND scope = $2 AND COALESCE(scope_target, '') = COALESCE($3, '')",
		tenantID, req.Scope, req.ScopeTarget,
	).Scan(&existingID)

	if err == nil {
		// Update existing
		_, err = dbPool.Exec(c.Request.Context(), `
			UPDATE automation_controls
			SET mode = $1, enabled = $2, updated_at = NOW(), created_by = $3
			WHERE id = $4 AND tenant_id = $5
		`, req.Mode, enabled, userID, existingID, tenantID)
		if err != nil {
			respondInternalError(c, err, "update automation control")
			return
		}

		// Audit log
		logKillSwitchAudit(c, tenantID, existingID, userID, "control_updated",
			fmt.Sprintf("Updated control: scope=%s target=%s mode=%s", req.Scope, req.ScopeTarget, req.Mode))

		c.JSON(http.StatusOK, gin.H{
			"id":      existingID,
			"status":  "updated",
			"scope":   req.Scope,
			"mode":    req.Mode,
			"enabled": enabled,
		})
		return
	}

	// Create new
	controlID := uuid.New().String()
	_, err = dbPool.Exec(c.Request.Context(), `
		INSERT INTO automation_controls (id, tenant_id, scope, scope_target, mode, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, controlID, tenantID, req.Scope, req.ScopeTarget, req.Mode, enabled, userID)
	if err != nil {
		respondInternalError(c, err, "create automation control")
		return
	}

	// Audit log
	logKillSwitchAudit(c, tenantID, controlID, userID, "control_created",
		fmt.Sprintf("Created control: scope=%s target=%s mode=%s", req.Scope, req.ScopeTarget, req.Mode))

	c.JSON(http.StatusCreated, gin.H{
		"id":      controlID,
		"status":  "created",
		"scope":   req.Scope,
		"mode":    req.Mode,
		"enabled": enabled,
	})
}

// POST /api/v1/automation/kill — emergency kill switch (admin only)
func emergencyKillHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Scope       string `json:"scope" binding:"required"`
		ScopeTarget string `json:"scope_target"`
		Reason      string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate scope
	if req.Scope != "tenant" && req.Scope != "workflow" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kill scope must be 'tenant' or 'workflow'"})
		return
	}

	// INSTANTANEOUS: Direct DB update, no queue
	now := time.Now()

	if req.Scope == "tenant" {
		// Kill ALL automation for tenant — disable every control
		_, err := dbPool.Exec(c.Request.Context(), `
			UPDATE automation_controls
			SET mode = 'disabled', enabled = false, kill_reason = $1, updated_at = $2
			WHERE tenant_id = $3
		`, req.Reason, now, tenantID)
		if err != nil {
			respondInternalError(c, err, "execute tenant kill switch")
			return
		}

		// Also insert/update a tenant-level control to ensure it exists
		controlID := uuid.New().String()
		_, _ = dbPool.Exec(c.Request.Context(), `
			INSERT INTO automation_controls (id, tenant_id, scope, scope_target, mode, enabled, kill_reason, created_by)
			VALUES ($1, $2, 'tenant', NULL, 'disabled', false, $3, $4)
			ON CONFLICT (tenant_id, scope, COALESCE(scope_target, ''))
			DO UPDATE SET mode = 'disabled', enabled = false, kill_reason = $3, updated_at = NOW()
		`, controlID, tenantID, req.Reason, userID)
	} else {
		// Kill specific workflow
		controlID := uuid.New().String()
		_, err := dbPool.Exec(c.Request.Context(), `
			INSERT INTO automation_controls (id, tenant_id, scope, scope_target, mode, enabled, kill_reason, created_by)
			VALUES ($1, $2, 'workflow', $3, 'disabled', false, $4, $5)
			ON CONFLICT (tenant_id, scope, COALESCE(scope_target, ''))
			DO UPDATE SET mode = 'disabled', enabled = false, kill_reason = $4, updated_at = NOW()
		`, controlID, tenantID, req.ScopeTarget, req.Reason, userID)
		if err != nil {
			respondInternalError(c, err, "execute workflow kill switch")
			return
		}
	}

	// Log to kill_switch_audit
	auditID := uuid.New().String()
	_, _ = dbPool.Exec(c.Request.Context(), `
		INSERT INTO kill_switch_audit (id, tenant_id, action, scope, scope_target, reason, performed_by, performed_at)
		VALUES ($1, $2, 'kill', $3, $4, $5, $6, $7)
	`, auditID, tenantID, req.Scope, req.ScopeTarget, req.Reason, userID, now)

	// Audit log
	logKillSwitchAudit(c, tenantID, auditID, userID, "emergency_kill",
		fmt.Sprintf("KILL SWITCH ACTIVATED: scope=%s target=%s reason=%s", req.Scope, req.ScopeTarget, req.Reason))

	// Dispatch webhook notification
	go DispatchWebhook(tenantID, "kill_switch_activated", map[string]interface{}{
		"scope":        req.Scope,
		"scope_target": req.ScopeTarget,
		"reason":       req.Reason,
		"performed_by": userID,
		"timestamp":    now,
	})

	c.JSON(http.StatusOK, gin.H{
		"status":      "killed",
		"scope":       req.Scope,
		"scope_target": req.ScopeTarget,
		"reason":      req.Reason,
		"killed_at":   now,
	})
}

// POST /api/v1/automation/resume — resume after kill (admin only)
func resumeAutomationHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		ControlID     string `json:"control_id" binding:"required"`
		Reason        string `json:"reason" binding:"required"`
		ResumeMode    string `json:"resume_mode"`
		CooldownMins  *int   `json:"cooldown_minutes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default resume to shadow mode for safety
	resumeMode := "shadow"
	if req.ResumeMode != "" {
		validModes := map[string]bool{"shadow": true, "assisted": true, "autonomous": true}
		if !validModes[req.ResumeMode] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resume_mode; must be shadow, assisted, or autonomous"})
			return
		}
		resumeMode = req.ResumeMode
	}

	// Verify the control exists and belongs to tenant
	var scope string
	var scopeTarget *string
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT scope, scope_target FROM automation_controls WHERE id = $1 AND tenant_id = $2",
		req.ControlID, tenantID,
	).Scan(&scope, &scopeTarget)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "control not found"})
		return
	}

	now := time.Now()

	// Handle cooldown timer
	if req.CooldownMins != nil && *req.CooldownMins > 0 {
		cooldownUntil := now.Add(time.Duration(*req.CooldownMins) * time.Minute)
		_, err = dbPool.Exec(c.Request.Context(), `
			UPDATE automation_controls
			SET mode = $1, enabled = true, kill_reason = NULL, updated_at = $2, cooldown_until = $3
			WHERE id = $4 AND tenant_id = $5
		`, resumeMode, now, cooldownUntil, req.ControlID, tenantID)
	} else {
		_, err = dbPool.Exec(c.Request.Context(), `
			UPDATE automation_controls
			SET mode = $1, enabled = true, kill_reason = NULL, updated_at = $2, cooldown_until = NULL
			WHERE id = $3 AND tenant_id = $4
		`, resumeMode, now, req.ControlID, tenantID)
	}

	if err != nil {
		respondInternalError(c, err, "resume automation control")
		return
	}

	// Log to kill_switch_audit
	auditID := uuid.New().String()
	scopeTargetStr := ""
	if scopeTarget != nil {
		scopeTargetStr = *scopeTarget
	}
	_, _ = dbPool.Exec(c.Request.Context(), `
		INSERT INTO kill_switch_audit (id, tenant_id, action, scope, scope_target, reason, performed_by, performed_at)
		VALUES ($1, $2, 'resume', $3, $4, $5, $6, $7)
	`, auditID, tenantID, scope, scopeTargetStr, req.Reason, userID, now)

	// Audit log
	logKillSwitchAudit(c, tenantID, req.ControlID, userID, "automation_resumed",
		fmt.Sprintf("Resumed: control=%s mode=%s reason=%s", req.ControlID, resumeMode, req.Reason))

	c.JSON(http.StatusOK, gin.H{
		"status":      "resumed",
		"control_id":  req.ControlID,
		"mode":        resumeMode,
		"reason":      req.Reason,
		"resumed_at":  now,
	})
}

// GET /api/v1/automation/audit — kill switch audit log (admin only)
func getKillSwitchAuditHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	limitStr := c.DefaultQuery("limit", "50")
	limit := 50
	if v, err := fmt.Sscanf(limitStr, "%d", &limit); v == 0 || err != nil || limit < 1 || limit > 200 {
		limit = 50
	}

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, action, scope, scope_target, reason, performed_by, performed_at
		FROM kill_switch_audit
		WHERE tenant_id = $1
		ORDER BY performed_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		respondInternalError(c, err, "query kill switch audit log")
		return
	}
	defer rows.Close()

	var audits []map[string]interface{}
	for rows.Next() {
		var id, action, scope, performedBy string
		var scopeTarget, reason *string
		var performedAt time.Time

		if err := rows.Scan(&id, &action, &scope, &scopeTarget, &reason, &performedBy, &performedAt); err != nil {
			log.Printf("Error scanning kill switch audit row: %v", err)
			continue
		}

		audits = append(audits, map[string]interface{}{
			"id":           id,
			"action":       action,
			"scope":        scope,
			"scope_target": scopeTarget,
			"reason":       reason,
			"performed_by": performedBy,
			"performed_at": performedAt,
		})
	}

	if audits == nil {
		audits = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"audit_log": audits, "count": len(audits)})
}

// logKillSwitchAudit writes an audit event for kill switch operations
func logKillSwitchAudit(c *gin.Context, tenantID, resourceID, userID, action, details string) {
	detailsJSON, _ := json.Marshal(map[string]interface{}{
		"message":    details,
		"user_id":    userID,
		"timestamp":  time.Now(),
	})
	_, err := dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, action, "automation_control", resourceID, string(detailsJSON),
	)
	if err != nil {
		log.Printf("Kill switch audit log failed: %v", err)
	}
}
