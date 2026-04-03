package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// ADMIN CONFIG HANDLERS — System Configuration CRUD + Audit
// All handlers use beginTenantTx() for RLS-safe DB access.
// ============================================================

// ---------- Ingest-pause cache (1-second Redis TTL) ----------

var (
	ingestPauseCache     map[string]ingestPauseCacheEntry
	ingestPauseCacheMu   sync.RWMutex
	ingestPauseCacheInit sync.Once
)

type ingestPauseCacheEntry struct {
	paused    bool
	fetchedAt time.Time
}

func initIngestPauseCache() {
	ingestPauseCacheInit.Do(func() {
		ingestPauseCache = make(map[string]ingestPauseCacheEntry)
	})
}

// isIngestPaused checks the "ingest.circuit_breaker_active" config key.
// Uses a 1-second in-memory cache per tenant. Fail-open on any error.
func isIngestPaused(ctx context.Context, tenantID string) bool {
	initIngestPauseCache()

	cacheKey := tenantID

	// Check cache first
	ingestPauseCacheMu.RLock()
	entry, found := ingestPauseCache[cacheKey]
	ingestPauseCacheMu.RUnlock()

	if found && time.Since(entry.fetchedAt) < 1*time.Second {
		return entry.paused
	}

	// Try Redis first (shared across API instances)
	paused := false
	redisCacheKey := fmt.Sprintf("zovark:ingest_paused:%s", tenantID)

	if redisClient != nil {
		val, err := redisClient.Get(ctx, redisCacheKey).Result()
		if err == nil {
			paused = val == "true"
			// Update in-memory cache
			ingestPauseCacheMu.Lock()
			ingestPauseCache[cacheKey] = ingestPauseCacheEntry{paused: paused, fetchedAt: time.Now()}
			ingestPauseCacheMu.Unlock()
			return paused
		}
	}

	// Fall back to DB
	if dbPool != nil {
		var configValue string
		err := dbPool.QueryRow(ctx,
			`SELECT config_value FROM system_configs
			 WHERE tenant_id = $1 AND config_key = 'ingest.circuit_breaker_active'`,
			tenantID,
		).Scan(&configValue)
		if err == nil {
			paused = configValue == "true"
		}
		// On error, fail-open (paused = false)

		// Populate Redis cache (best-effort, 2s TTL)
		if redisClient != nil {
			val := "false"
			if paused {
				val = "true"
			}
			_ = redisClient.Set(ctx, redisCacheKey, val, 2*time.Second).Err()
		}
	}

	// Update in-memory cache
	ingestPauseCacheMu.Lock()
	ingestPauseCache[cacheKey] = ingestPauseCacheEntry{paused: paused, fetchedAt: time.Now()}
	ingestPauseCacheMu.Unlock()

	return paused
}

// ---------- GET /api/v1/admin/config ----------
// Returns all configs for the tenant. Secret values are masked.

func handleConfigGetAll(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	rows, err := dbPool.Query(ctx,
		`SELECT id, config_key, config_value, is_secret, description, updated_by, created_at, updated_at
		 FROM system_configs
		 WHERE tenant_id = $1
		 ORDER BY config_key`,
		tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "list system configs")
		return
	}
	defer rows.Close()

	var configs []map[string]interface{}
	for rows.Next() {
		var id, key, value string
		var isSecret bool
		var description *string
		var updatedBy *string
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &key, &value, &isSecret, &description, &updatedBy, &createdAt, &updatedAt); err != nil {
			log.Printf("[CONFIG] Error scanning config row: %v", err)
			continue
		}

		displayValue := value
		if isSecret {
			displayValue = "***"
		}

		configs = append(configs, map[string]interface{}{
			"id":          id,
			"config_key":  key,
			"config_value": displayValue,
			"is_secret":   isSecret,
			"description": description,
			"updated_by":  updatedBy,
			"created_at":  createdAt.Format(time.RFC3339),
			"updated_at":  updatedAt.Format(time.RFC3339),
		})
	}

	if configs == nil {
		configs = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"configs": configs,
		"total":   len(configs),
	})
}

// ---------- GET /api/v1/admin/config/:key ----------
// Returns a single config by key. Secret values are masked.

func handleConfigGet(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	key := c.Param("key")
	ctx := c.Request.Context()

	var id, value string
	var isSecret bool
	var description *string
	var updatedBy *string
	var createdAt, updatedAt time.Time

	err := dbPool.QueryRow(ctx,
		`SELECT id, config_value, is_secret, description, updated_by, created_at, updated_at
		 FROM system_configs
		 WHERE tenant_id = $1 AND config_key = $2`,
		tenantID, key,
	).Scan(&id, &value, &isSecret, &description, &updatedBy, &createdAt, &updatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "config key not found"})
		return
	}

	displayValue := value
	if isSecret {
		displayValue = "***"
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          id,
		"config_key":  key,
		"config_value": displayValue,
		"is_secret":   isSecret,
		"description": description,
		"updated_by":  updatedBy,
		"created_at":  createdAt.Format(time.RFC3339),
		"updated_at":  updatedAt.Format(time.RFC3339),
	})
}

// ---------- PUT /api/v1/admin/config ----------
// Creates or updates a config key. Writes an audit entry.

func handleConfigUpsert(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.GetString("user_id")
	ctx := c.Request.Context()

	var req struct {
		ConfigKey   string  `json:"config_key" binding:"required"`
		ConfigValue string  `json:"config_value" binding:"required"`
		IsSecret    bool    `json:"is_secret"`
		Description *string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate key length
	if len(req.ConfigKey) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_key must be <= 255 characters"})
		return
	}
	if len(req.ConfigValue) > 10000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_value must be <= 10000 characters"})
		return
	}

	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin config upsert tx")
		return
	}
	defer tx.Rollback(ctx)

	// Check if key already exists
	var existingID string
	var oldValue string
	err = tx.QueryRow(ctx,
		`SELECT id, config_value FROM system_configs WHERE tenant_id = $1 AND config_key = $2`,
		tenantID, req.ConfigKey,
	).Scan(&existingID, &oldValue)

	action := "create"
	if err == nil {
		// Update existing
		action = "update"
		_, err = tx.Exec(ctx,
			`UPDATE system_configs
			 SET config_value = $1, is_secret = $2, description = $3, updated_by = $4
			 WHERE tenant_id = $5 AND config_key = $6`,
			req.ConfigValue, req.IsSecret, req.Description, userID, tenantID, req.ConfigKey,
		)
		if err != nil {
			respondInternalError(c, err, "update system config")
			return
		}
	} else {
		// Insert new
		_, err = tx.Exec(ctx,
			`INSERT INTO system_configs (tenant_id, config_key, config_value, is_secret, description, updated_by)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			tenantID, req.ConfigKey, req.ConfigValue, req.IsSecret, req.Description, userID,
		)
		if err != nil {
			respondInternalError(c, err, "insert system config")
			return
		}
	}

	// Write audit entry
	auditOldValue := ""
	if action == "update" {
		auditOldValue = oldValue
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO system_config_audit (tenant_id, config_key, old_value, new_value, action, changed_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tenantID, req.ConfigKey, auditOldValue, req.ConfigValue, action, userID,
	)
	if err != nil {
		respondInternalError(c, err, "write config audit entry")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit config upsert")
		return
	}

	// Invalidate ingest-pause cache if this key affects it
	if req.ConfigKey == "ingest.circuit_breaker_active" {
		initIngestPauseCache()
		ingestPauseCacheMu.Lock()
		delete(ingestPauseCache, tenantID)
		ingestPauseCacheMu.Unlock()
		if redisClient != nil {
			_ = redisClient.Del(ctx, fmt.Sprintf("zovark:ingest_paused:%s", tenantID)).Err()
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     action + "d",
		"config_key": req.ConfigKey,
	})
}

// ---------- DELETE /api/v1/admin/config/:key ----------
// Deletes a config key. Writes an audit entry.

func handleConfigDelete(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.GetString("user_id")
	key := c.Param("key")
	ctx := c.Request.Context()

	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin config delete tx")
		return
	}
	defer tx.Rollback(ctx)

	// Get the old value for audit
	var oldValue string
	err = tx.QueryRow(ctx,
		`SELECT config_value FROM system_configs WHERE tenant_id = $1 AND config_key = $2`,
		tenantID, key,
	).Scan(&oldValue)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "config key not found"})
		return
	}

	// Delete
	_, err = tx.Exec(ctx,
		`DELETE FROM system_configs WHERE tenant_id = $1 AND config_key = $2`,
		tenantID, key,
	)
	if err != nil {
		respondInternalError(c, err, "delete system config")
		return
	}

	// Write audit entry
	_, err = tx.Exec(ctx,
		`INSERT INTO system_config_audit (tenant_id, config_key, old_value, new_value, action, changed_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tenantID, key, oldValue, "", "delete", userID,
	)
	if err != nil {
		respondInternalError(c, err, "write config delete audit")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit config delete")
		return
	}

	// Invalidate cache
	if key == "ingest.circuit_breaker_active" {
		initIngestPauseCache()
		ingestPauseCacheMu.Lock()
		delete(ingestPauseCache, tenantID)
		ingestPauseCacheMu.Unlock()
		if redisClient != nil {
			_ = redisClient.Del(ctx, fmt.Sprintf("zovark:ingest_paused:%s", tenantID)).Err()
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "deleted",
		"config_key": key,
	})
}

// ---------- POST /api/v1/admin/config/:key/rollback/:audit_id ----------
// Restores a config key to the old_value from a given audit entry.

func handleConfigRollback(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.GetString("user_id")
	key := c.Param("key")
	auditID := c.Param("audit_id")
	ctx := c.Request.Context()

	// Look up the audit entry
	var auditOldValue *string
	var auditKey string
	err := dbPool.QueryRow(ctx,
		`SELECT config_key, old_value FROM system_config_audit
		 WHERE id = $1 AND tenant_id = $2`,
		auditID, tenantID,
	).Scan(&auditKey, &auditOldValue)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "audit entry not found"})
		return
	}

	if auditKey != key {
		c.JSON(http.StatusBadRequest, gin.H{"error": "audit entry does not match config key"})
		return
	}

	if auditOldValue == nil || *auditOldValue == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "audit entry has no old_value to restore"})
		return
	}

	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "begin config rollback tx")
		return
	}
	defer tx.Rollback(ctx)

	// Get current value for audit trail
	var currentValue string
	err = tx.QueryRow(ctx,
		`SELECT config_value FROM system_configs WHERE tenant_id = $1 AND config_key = $2`,
		tenantID, key,
	).Scan(&currentValue)
	if err != nil {
		// Config was deleted — re-create it
		_, err = tx.Exec(ctx,
			`INSERT INTO system_configs (tenant_id, config_key, config_value, updated_by)
			 VALUES ($1, $2, $3, $4)`,
			tenantID, key, *auditOldValue, userID,
		)
		if err != nil {
			respondInternalError(c, err, "re-create config on rollback")
			return
		}
		currentValue = ""
	} else {
		// Update existing
		_, err = tx.Exec(ctx,
			`UPDATE system_configs SET config_value = $1, updated_by = $2
			 WHERE tenant_id = $3 AND config_key = $4`,
			*auditOldValue, userID, tenantID, key,
		)
		if err != nil {
			respondInternalError(c, err, "update config on rollback")
			return
		}
	}

	// Write rollback audit entry
	_, err = tx.Exec(ctx,
		`INSERT INTO system_config_audit (tenant_id, config_key, old_value, new_value, action, changed_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tenantID, key, currentValue, *auditOldValue, "rollback", userID,
	)
	if err != nil {
		respondInternalError(c, err, "write rollback audit")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit config rollback")
		return
	}

	// Invalidate cache
	if key == "ingest.circuit_breaker_active" {
		initIngestPauseCache()
		ingestPauseCacheMu.Lock()
		delete(ingestPauseCache, tenantID)
		ingestPauseCacheMu.Unlock()
		if redisClient != nil {
			_ = redisClient.Del(ctx, fmt.Sprintf("zovark:ingest_paused:%s", tenantID)).Err()
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         "rolled_back",
		"config_key":     key,
		"restored_value": *auditOldValue,
		"from_audit_id":  auditID,
	})
}

// ---------- GET /api/v1/admin/config/audit ----------
// Paginated audit log for config changes.

func handleConfigAuditLog(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	ctx := c.Request.Context()

	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	filterKey := c.Query("config_key")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 200 {
		limit = 50
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// Build query
	query := `SELECT id, config_key, old_value, new_value, action, changed_by, changed_at
	          FROM system_config_audit
	          WHERE tenant_id = $1`
	countQuery := `SELECT COUNT(*) FROM system_config_audit WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	countArgs := []interface{}{tenantID}

	if filterKey != "" {
		query += ` AND config_key = $2`
		countQuery += ` AND config_key = $2`
		args = append(args, filterKey)
		countArgs = append(countArgs, filterKey)
	}

	// Total count
	var total int
	_ = dbPool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)

	query += ` ORDER BY changed_at DESC`
	if filterKey != "" {
		query += ` LIMIT $3 OFFSET $4`
	} else {
		query += ` LIMIT $2 OFFSET $3`
	}
	args = append(args, limit, offset)

	rows, err := dbPool.Query(ctx, query, args...)
	if err != nil {
		respondInternalError(c, err, "query config audit log")
		return
	}
	defer rows.Close()

	var entries []map[string]interface{}
	for rows.Next() {
		var id, configKey, newValue, action string
		var oldValue *string
		var changedBy *string
		var changedAt time.Time

		if err := rows.Scan(&id, &configKey, &oldValue, &newValue, &action, &changedBy, &changedAt); err != nil {
			log.Printf("[CONFIG] Error scanning audit row: %v", err)
			continue
		}

		entries = append(entries, map[string]interface{}{
			"id":         id,
			"config_key": configKey,
			"old_value":  oldValue,
			"new_value":  newValue,
			"action":     action,
			"changed_by": changedBy,
			"changed_at": changedAt.Format(time.RFC3339),
		})
	}

	if entries == nil {
		entries = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}
