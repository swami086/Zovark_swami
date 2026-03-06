package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// SECURITY HEADERS
// ============================================================

func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}

// ============================================================
// AUTH RATE LIMITING (in-memory, per-IP)
// ============================================================

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	limit    int
}

var authLimiter = &rateLimiter{
	attempts: make(map[string][]time.Time),
	window:   15 * time.Minute,
	limit:    10, // 10 attempts per 15 minutes per IP
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean old entries
	var valid []time.Time
	for _, t := range rl.attempts[key] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.attempts[key] = valid

	if len(valid) >= rl.limit {
		return false
	}

	rl.attempts[key] = append(rl.attempts[key], now)
	return true
}

func authRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !authLimiter.allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many authentication attempts. Try again later.",
			})
			return
		}
		c.Next()
	}
}

// ============================================================
// AUDIT MIDDLEWARE — logs all mutating API calls
// ============================================================

func auditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Only audit mutating requests that succeeded
		method := c.Request.Method
		if method != "POST" && method != "PUT" && method != "DELETE" {
			return
		}
		if c.Writer.Status() >= 400 {
			return
		}

		tenantID, _ := c.Get("tenant_id")
		userID, _ := c.Get("user_id")

		action := fmt.Sprintf("api_%s_%s", method, c.FullPath())
		details := fmt.Sprintf(`{"method": "%s", "path": "%s", "status": %d, "ip": "%s"}`,
			method, c.Request.URL.Path, c.Writer.Status(), c.ClientIP())

		go func() {
			_, err := dbPool.Exec(context.Background(),
				"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
				tenantID, action, "api", userID, details,
			)
			if err != nil {
				log.Printf("Audit log failed: %v", err)
			}
		}()
	}
}

// ============================================================
// ACCOUNT LOCKOUT
// ============================================================

func checkAccountLocked(email string) bool {
	var lockedUntil *time.Time
	err := dbPool.QueryRow(context.Background(),
		"SELECT locked_until FROM users WHERE email = $1", email,
	).Scan(&lockedUntil)
	if err != nil {
		return false
	}
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		return true
	}
	return false
}

func recordFailedLogin(email string) {
	_, _ = dbPool.Exec(context.Background(),
		"UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE email = $1", email)

	// Lock account after 5 failed attempts
	var attempts int
	_ = dbPool.QueryRow(context.Background(),
		"SELECT failed_login_attempts FROM users WHERE email = $1", email,
	).Scan(&attempts)

	if attempts >= 5 {
		lockUntil := time.Now().Add(30 * time.Minute)
		_, _ = dbPool.Exec(context.Background(),
			"UPDATE users SET locked_until = $1 WHERE email = $2", lockUntil, email)
	}
}

func recordSuccessfulLogin(email string) {
	_, _ = dbPool.Exec(context.Background(),
		"UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE email = $1", email)
}

// ============================================================
// DATA RETENTION
// ============================================================

func listRetentionPoliciesHandler(c *gin.Context) {
	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, table_name, retention_days, delete_strategy, is_active, last_cleanup_at, rows_cleaned FROM data_retention_policies ORDER BY table_name",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query retention policies"})
		return
	}
	defer rows.Close()

	var policies []map[string]interface{}
	for rows.Next() {
		var id, tableName, strategy string
		var retentionDays, rowsCleaned int
		var isActive bool
		var lastCleanup *time.Time

		if err := rows.Scan(&id, &tableName, &retentionDays, &strategy, &isActive, &lastCleanup, &rowsCleaned); err != nil {
			continue
		}

		policies = append(policies, map[string]interface{}{
			"id":              id,
			"table_name":      tableName,
			"retention_days":  retentionDays,
			"delete_strategy": strategy,
			"is_active":       isActive,
			"last_cleanup_at": lastCleanup,
			"rows_cleaned":    rowsCleaned,
		})
	}

	if policies == nil {
		policies = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies, "count": len(policies)})
}

func updateRetentionPolicyHandler(c *gin.Context) {
	policyID := c.Param("id")

	var req struct {
		RetentionDays *int  `json:"retention_days"`
		IsActive      *bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.RetentionDays != nil {
		_, _ = dbPool.Exec(c.Request.Context(),
			"UPDATE data_retention_policies SET retention_days = $1 WHERE id = $2",
			*req.RetentionDays, policyID)
	}
	if req.IsActive != nil {
		_, _ = dbPool.Exec(c.Request.Context(),
			"UPDATE data_retention_policies SET is_active = $1 WHERE id = $2",
			*req.IsActive, policyID)
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}
