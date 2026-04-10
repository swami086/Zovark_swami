package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const mcpKeyPrefix = "zvk_mcp_"

func generateMCPAPIKey() (rawKey string, keyHash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	rawKey = mcpKeyPrefix + base64.URLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(rawKey))
	keyHash = hex.EncodeToString(h[:])
	return rawKey, keyHash
}

// POST /api/v1/mcp-keys
func createMCPKeyHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	raw, hash := generateMCPAPIKey()
	id := uuid.New().String()

	_, err := dbPool.Exec(c.Request.Context(),
		`INSERT INTO mcp_api_keys (id, tenant_id, created_by, name, key_hash)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, tenantID, userID, req.Name, hash,
	)
	if err != nil {
		log.Printf("create mcp key: %v", err)
		respondInternalError(c, err, "create mcp api key")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":         id,
		"name":       req.Name,
		"key":        raw,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/v1/mcp-keys
func listMCPKeysHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, name, last_used_at, created_at, revoked_at
		FROM mcp_api_keys
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "list mcp api keys")
		return
	}
	defer rows.Close()

	var items []gin.H
	for rows.Next() {
		var id, name string
		var lastUsed sql.NullTime
		var createdAt time.Time
		var revokedAt *time.Time
		if err := rows.Scan(&id, &name, &lastUsed, &createdAt, &revokedAt); err != nil {
			respondInternalError(c, err, "scan mcp key")
			return
		}
		active := revokedAt == nil
		item := gin.H{
			"id": id, "name": name, "created_at": createdAt.Format(time.RFC3339), "active": active,
		}
		if lastUsed.Valid {
			item["last_used_at"] = lastUsed.Time.Format(time.RFC3339)
		}
		if revokedAt != nil {
			item["revoked_at"] = revokedAt.Format(time.RFC3339)
		}
		items = append(items, item)
	}
	if items == nil {
		items = []gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// DELETE /api/v1/mcp-keys/:id
func revokeMCPKeyHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	id := c.Param("id")

	cmd, err := dbPool.Exec(c.Request.Context(), `
		UPDATE mcp_api_keys SET revoked_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, id, tenantID)
	if err != nil {
		respondInternalError(c, err, "revoke mcp api key")
		return
	}
	if cmd.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found or already revoked"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "id": id})
}
