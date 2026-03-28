package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================
// TENANT CRUD
// ============================================================

func listTenantsHandler(c *gin.Context) {
	// Scope to caller's own tenant (Security P0#8 — prevent cross-tenant enumeration)
	callerTenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, name, slug, tier, settings, is_active, max_concurrent, created_at FROM tenants WHERE id = $1 ORDER BY created_at DESC",
		callerTenantID,
	)
	if err != nil {
		respondInternalError(c, err, "query tenants")
		return
	}
	defer rows.Close()

	var tenants []map[string]interface{}
	for rows.Next() {
		var id, name, slug, tier string
		var settings map[string]interface{}
		var isActive bool
		var maxConcurrent int
		var createdAt time.Time

		if err := rows.Scan(&id, &name, &slug, &tier, &settings, &isActive, &maxConcurrent, &createdAt); err != nil {
			log.Printf("Error scanning tenant row: %v", err)
			continue
		}

		tenants = append(tenants, map[string]interface{}{
			"id":             id,
			"name":           name,
			"slug":           slug,
			"tier":           tier,
			"settings":       settings,
			"is_active":      isActive,
			"max_concurrent": maxConcurrent,
			"created_at":     createdAt,
		})
	}

	if tenants == nil {
		tenants = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"tenants": tenants, "count": len(tenants)})
}

func getTenantHandler(c *gin.Context) {
	tenantID := c.Param("id")
	callerTenantID := c.MustGet("tenant_id").(string)

	// Security P0#8: admin can only view their own tenant
	if tenantID != callerTenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied: cannot view other tenants"})
		return
	}

	var name, slug, tier string
	var settings map[string]interface{}
	var isActive bool
	var maxConcurrent int
	var createdAt, updatedAt time.Time

	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT name, slug, tier, settings, is_active, max_concurrent, created_at, updated_at FROM tenants WHERE id = $1",
		tenantID,
	).Scan(&name, &slug, &tier, &settings, &isActive, &maxConcurrent, &createdAt, &updatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}

	// Get user count
	var userCount int
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM users WHERE tenant_id = $1", tenantID,
	).Scan(&userCount)

	// Get task count
	var taskCount int
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM agent_tasks WHERE tenant_id = $1", tenantID,
	).Scan(&taskCount)

	c.JSON(http.StatusOK, gin.H{
		"id":             tenantID,
		"name":           name,
		"slug":           slug,
		"tier":           tier,
		"settings":       settings,
		"is_active":      isActive,
		"max_concurrent": maxConcurrent,
		"user_count":     userCount,
		"task_count":     taskCount,
		"created_at":     createdAt,
		"updated_at":     updatedAt,
	})
}

func createTenantHandler(c *gin.Context) {
	var req struct {
		Name          string `json:"name" binding:"required"`
		Slug          string `json:"slug" binding:"required"`
		Tier          string `json:"tier"`
		MaxConcurrent *int   `json:"max_concurrent"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Tier == "" {
		req.Tier = "free"
	}
	maxConcurrent := 50
	if req.MaxConcurrent != nil {
		maxConcurrent = *req.MaxConcurrent
	}

	tenantID := uuid.New().String()
	_, err := dbPool.Exec(c.Request.Context(),
		"INSERT INTO tenants (id, name, slug, tier, max_concurrent) VALUES ($1, $2, $3, $4, $5)",
		tenantID, req.Name, req.Slug, req.Tier, maxConcurrent,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "tenant slug already exists"})
			return
		}
		respondInternalError(c, err, "create tenant")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":             tenantID,
		"name":           req.Name,
		"slug":           req.Slug,
		"tier":           req.Tier,
		"max_concurrent": maxConcurrent,
	})
}

func updateTenantHandler(c *gin.Context) {
	tenantID := c.Param("id")
	callerTenantID := c.MustGet("tenant_id").(string)

	// Security P0#8: admin can only update their own tenant
	if tenantID != callerTenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied: cannot modify other tenants"})
		return
	}

	var req struct {
		Name          *string                `json:"name"`
		Tier          *string                `json:"tier"`
		Settings      map[string]interface{} `json:"settings"`
		IsActive      *bool                  `json:"is_active"`
		MaxConcurrent *int                   `json:"max_concurrent"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify exists
	var exists bool
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)", tenantID,
	).Scan(&exists)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}

	if req.Name != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE tenants SET name = $1, updated_at = NOW() WHERE id = $2", *req.Name, tenantID)
	}
	if req.Tier != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE tenants SET tier = $1, updated_at = NOW() WHERE id = $2", *req.Tier, tenantID)
	}
	if req.Settings != nil {
		settingsJSON, _ := json.Marshal(req.Settings)
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE tenants SET settings = $1, updated_at = NOW() WHERE id = $2", settingsJSON, tenantID)
	}
	if req.IsActive != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE tenants SET is_active = $1, updated_at = NOW() WHERE id = $2", *req.IsActive, tenantID)
	}
	if req.MaxConcurrent != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE tenants SET max_concurrent = $1, updated_at = NOW() WHERE id = $2", *req.MaxConcurrent, tenantID)
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ============================================================
// WEBHOOK ENDPOINT CRUD
// ============================================================

func generateSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func listWebhookEndpointsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, name, url, event_types, is_active, created_at FROM webhook_endpoints WHERE tenant_id = $1 ORDER BY created_at DESC",
		tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "query webhook endpoints")
		return
	}
	defer rows.Close()

	var endpoints []map[string]interface{}
	for rows.Next() {
		var id, name, url string
		var eventTypes []string
		var isActive bool
		var createdAt time.Time

		if err := rows.Scan(&id, &name, &url, &eventTypes, &isActive, &createdAt); err != nil {
			log.Printf("Error scanning webhook endpoint: %v", err)
			continue
		}

		endpoints = append(endpoints, map[string]interface{}{
			"id":          id,
			"name":        name,
			"url":         url,
			"event_types": eventTypes,
			"is_active":   isActive,
			"created_at":  createdAt,
		})
	}

	if endpoints == nil {
		endpoints = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"endpoints": endpoints, "count": len(endpoints)})
}

func createWebhookEndpointHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var req struct {
		Name       string   `json:"name" binding:"required"`
		URL        string   `json:"url" binding:"required"`
		EventTypes []string `json:"event_types" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate event types
	validEvents := map[string]bool{
		"investigation_completed": true,
		"alert_received":          true,
		"approval_needed":         true,
		"response_executed":       true,
	}
	for _, et := range req.EventTypes {
		if !validEvents[et] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid event type: %s", et)})
			return
		}
	}

	endpointID := uuid.New().String()
	secret := generateSecret()

	_, err := dbPool.Exec(c.Request.Context(),
		"INSERT INTO webhook_endpoints (id, tenant_id, name, url, secret, event_types) VALUES ($1, $2, $3, $4, $5, $6)",
		endpointID, tenantID, req.Name, req.URL, secret, req.EventTypes,
	)
	if err != nil {
		respondInternalError(c, err, "create webhook endpoint")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":          endpointID,
		"name":        req.Name,
		"url":         req.URL,
		"secret":      secret,
		"event_types": req.EventTypes,
	})
}

func updateWebhookEndpointHandler(c *gin.Context) {
	endpointID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	var req struct {
		Name       *string  `json:"name"`
		URL        *string  `json:"url"`
		EventTypes []string `json:"event_types"`
		IsActive   *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var exists bool
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM webhook_endpoints WHERE id = $1 AND tenant_id = $2)", endpointID, tenantID,
	).Scan(&exists)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook endpoint not found"})
		return
	}

	if req.Name != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE webhook_endpoints SET name = $1, updated_at = NOW() WHERE id = $2", *req.Name, endpointID)
	}
	if req.URL != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE webhook_endpoints SET url = $1, updated_at = NOW() WHERE id = $2", *req.URL, endpointID)
	}
	if req.EventTypes != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE webhook_endpoints SET event_types = $1, updated_at = NOW() WHERE id = $2", req.EventTypes, endpointID)
	}
	if req.IsActive != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE webhook_endpoints SET is_active = $1, updated_at = NOW() WHERE id = $2", *req.IsActive, endpointID)
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func deleteWebhookEndpointHandler(c *gin.Context) {
	endpointID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	result, err := dbPool.Exec(c.Request.Context(),
		"UPDATE webhook_endpoints SET is_active = false, updated_at = NOW() WHERE id = $1 AND tenant_id = $2",
		endpointID, tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "deactivate webhook endpoint")
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "endpoint not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deactivated"})
}

func listWebhookDeliveriesHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, endpoint_id, event_type, status, http_status, attempts, created_at FROM webhook_deliveries WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 50",
		tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "query webhook deliveries")
		return
	}
	defer rows.Close()

	var deliveries []map[string]interface{}
	for rows.Next() {
		var id, endpointID, eventType, status string
		var httpStatus *int
		var attempts int
		var createdAt time.Time

		if err := rows.Scan(&id, &endpointID, &eventType, &status, &httpStatus, &attempts, &createdAt); err != nil {
			continue
		}

		deliveries = append(deliveries, map[string]interface{}{
			"id":          id,
			"endpoint_id": endpointID,
			"event_type":  eventType,
			"status":      status,
			"http_status": httpStatus,
			"attempts":    attempts,
			"created_at":  createdAt,
		})
	}

	if deliveries == nil {
		deliveries = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"deliveries": deliveries, "count": len(deliveries)})
}

// ============================================================
// WEBHOOK DELIVERY ENGINE
// ============================================================

// DispatchWebhook sends an event to all active webhook endpoints for a tenant
func DispatchWebhook(tenantID, eventType string, payload map[string]interface{}) {
	rows, err := dbPool.Query(context.Background(),
		"SELECT id, url, secret FROM webhook_endpoints WHERE tenant_id = $1 AND is_active = true AND $2 = ANY(event_types)",
		tenantID, eventType,
	)
	if err != nil {
		log.Printf("Webhook dispatch query failed: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var endpointID, url, secret string
		if err := rows.Scan(&endpointID, &url, &secret); err != nil {
			continue
		}

		go deliverWebhook(tenantID, endpointID, url, secret, eventType, payload)
	}
}

func deliverWebhook(tenantID, endpointID, url, secret, eventType string, payload map[string]interface{}) {
	body, _ := json.Marshal(map[string]interface{}{
		"event_type": eventType,
		"tenant_id":  tenantID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"data":       payload,
	})

	// Create delivery record
	deliveryID := uuid.New().String()
	_, _ = dbPool.Exec(context.Background(),
		"INSERT INTO webhook_deliveries (id, endpoint_id, tenant_id, event_type, payload, status) VALUES ($1, $2, $3, $4, $5, 'pending')",
		deliveryID, endpointID, tenantID, eventType, body,
	)

	// Attempt delivery with retries
	maxAttempts := 3
	var lastErr error
	var httpStatus int

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		httpStatus, lastErr = attemptDelivery(url, secret, body)
		if lastErr == nil && httpStatus >= 200 && httpStatus < 300 {
			_, _ = dbPool.Exec(context.Background(),
				"UPDATE webhook_deliveries SET status = 'delivered', http_status = $1, attempts = $2, last_attempt_at = NOW() WHERE id = $3",
				httpStatus, attempt, deliveryID,
			)
			return
		}

		if attempt < maxAttempts {
			// Exponential backoff: 1s, 4s
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
		}
	}

	// All retries exhausted
	errMsg := ""
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	_, _ = dbPool.Exec(context.Background(),
		"UPDATE webhook_deliveries SET status = 'failed', http_status = $1, attempts = $2, last_attempt_at = NOW(), response_body = $3 WHERE id = $4",
		httpStatus, maxAttempts, errMsg, deliveryID,
	)
}

func attemptDelivery(url, secret string, body []byte) (int, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ZOVARK-Webhook/1.0")

	// HMAC-SHA256 signature
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Webhook-Signature", sig)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}
