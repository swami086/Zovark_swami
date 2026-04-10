package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// --------------------------------------------------------------------------
// Governance Configuration API
//
// Provides 2 endpoints for managing investigation autonomy levels per task type:
//   GET /api/v1/governance/config  -- list governance config for the tenant
//   PUT /api/v1/governance/config  -- upsert autonomy_level for a task_type
// --------------------------------------------------------------------------

// getGovernanceConfigHandler returns all governance_config rows for the authenticated tenant.
// GET /api/v1/governance/config
func getGovernanceConfigHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)

	if dbPool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	rows, err := dbPool.Query(ctx, `
		SELECT id, tenant_id, task_type, autonomy_level,
		       consecutive_correct, upgrade_threshold,
		       created_at, updated_at
		FROM governance_config
		WHERE tenant_id = $1
		ORDER BY task_type ASC
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query governance config")
		return
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var id, tid, taskType, autonomyLevel string
		var consecutiveCorrect, upgradeThreshold int
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &tid, &taskType, &autonomyLevel,
			&consecutiveCorrect, &upgradeThreshold,
			&createdAt, &updatedAt); err != nil {
			respondInternalError(c, err, "scan governance config row")
			return
		}

		items = append(items, map[string]interface{}{
			"id":                   id,
			"tenant_id":            tid,
			"task_type":            taskType,
			"autonomy_level":       autonomyLevel,
			"consecutive_correct":  consecutiveCorrect,
			"upgrade_threshold":    upgradeThreshold,
			"created_at":           createdAt,
			"updated_at":           updatedAt,
		})
	}

	if items == nil {
		items = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"items": items,
		"count": len(items),
	})
}

// governanceConfigUpdateRequest is the JSON body for the PUT endpoint.
type governanceConfigUpdateRequest struct {
	TaskType      string `json:"task_type" binding:"required"`
	AutonomyLevel string `json:"autonomy_level" binding:"required"`
}

// updateGovernanceConfigHandler upserts a governance_config row for a tenant + task_type.
// PUT /api/v1/governance/config
func updateGovernanceConfigHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)

	if dbPool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	var req governanceConfigUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate autonomy_level
	validLevels := map[string]bool{
		"observe":    true,
		"assist":     true,
		"autonomous": true,
	}
	if !validLevels[req.AutonomyLevel] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "autonomy_level must be one of: observe, assist, autonomous",
		})
		return
	}

	// UPSERT into governance_config using tenant RLS transaction
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin governance config transaction")
		return
	}
	defer tx.Rollback(ctx)

	var prev sql.NullString
	if err := tx.QueryRow(ctx,
		`SELECT autonomy_level FROM governance_config WHERE tenant_id = $1 AND task_type = $2`,
		tenantID, req.TaskType,
	).Scan(&prev); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		respondInternalError(c, err, "read governance config")
		return
	}

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO governance_config (tenant_id, task_type, autonomy_level, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (tenant_id, task_type)
		DO UPDATE SET autonomy_level = EXCLUDED.autonomy_level, updated_at = NOW()
		RETURNING id
	`, tenantID, req.TaskType, req.AutonomyLevel).Scan(&id)
	if err != nil {
		respondInternalError(c, err, "upsert governance config")
		return
	}

	prevVal := ""
	if prev.Valid {
		prevVal = prev.String
	}
	meta, _ := json.Marshal(map[string]interface{}{
		"task_type":      req.TaskType,
		"previous_value": prevVal,
		"new_value":      req.AutonomyLevel,
	})
	uid := c.GetString("user_id")
	var actorUUID *uuid.UUID
	if uid != "" {
		if u, err := uuid.Parse(uid); err == nil {
			actorUUID = &u
		}
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events (tenant_id, event_type, actor_id, actor_type, resource_type, resource_id, metadata)
		 VALUES ($1, 'governance_config_updated', $2, 'user', 'governance_config', $3::uuid, $4)`,
		tenantID, actorUUID, id, meta,
	); err != nil {
		respondInternalError(c, err, "insert governance audit_events")
		return
	}

	// Legacy agent_audit_log (compat)
	if _, err := tx.Exec(ctx,
		`INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id)
		 VALUES ($1, $2, $3, $4)`,
		tenantID, "governance_config_updated", "governance_config", id,
	); err != nil {
		respondInternalError(c, err, "insert governance agent_audit_log")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit governance config transaction")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":             id,
		"tenant_id":      tenantID,
		"task_type":      req.TaskType,
		"autonomy_level": req.AutonomyLevel,
		"status":         "updated",
	})
}
