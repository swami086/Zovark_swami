package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ============================================================
// BREAK-GLASS EMERGENCY AUTH
// Provides an emergency login endpoint when normal auth is unavailable
// (e.g., OIDC provider down, admin account locked, DB user table corrupt).
//
// - Reads ZOVARK_BREAKGLASS_PASSWORD_HASH from env (bcrypt hash)
// - Returns 404 if not configured (endpoint effectively disabled)
// - 3 attempts/minute/IP rate limit (in-memory)
// - ALL attempts logged to audit_events
// - 15-minute JWT with role=admin
// ============================================================

// ---------- In-memory rate limiter (per IP) ----------

type breakglassRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

var bgRateLimiter = &breakglassRateLimiter{
	attempts: make(map[string][]time.Time),
}

// isRateLimited returns true if the IP has exceeded 3 attempts in the last minute.
func (rl *breakglassRateLimiter) isRateLimited(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	// Prune old entries
	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	rl.attempts[ip] = recent

	return len(recent) >= 3
}

// record adds an attempt timestamp for the IP.
func (rl *breakglassRateLimiter) record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

// ---------- Audit logging ----------

func logBreakglassAttempt(ctx context.Context, ip string, success bool, detail string) {
	if dbPool == nil {
		log.Printf("[BREAKGLASS] DB unavailable, logging to stdout: ip=%s success=%v detail=%s", ip, success, detail)
		return
	}

	metadata, _ := json.Marshal(map[string]interface{}{
		"ip":      ip,
		"success": success,
		"detail":  detail,
	})

	_, err := dbPool.Exec(ctx,
		`INSERT INTO audit_events (tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		"00000000-0000-0000-0000-000000000000", // system-level event
		"breakglass_login_attempt",
		"system",
		"auth",
		ip,
		metadata,
	)
	if err != nil {
		log.Printf("[BREAKGLASS] Failed to write audit event: %v", err)
	}
}

// ---------- POST /api/v1/admin/breakglass/login ----------

func handleBreakglassLogin(c *gin.Context) {
	passwordHash := os.Getenv("ZOVARK_BREAKGLASS_PASSWORD_HASH")

	// If not configured, endpoint is effectively disabled
	if passwordHash == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	clientIP := c.ClientIP()

	// Rate limit check
	if bgRateLimiter.isRateLimited(clientIP) {
		logBreakglassAttempt(c.Request.Context(), clientIP, false, "rate_limited")
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "too many attempts, try again in 1 minute",
		})
		return
	}

	// Record attempt before processing
	bgRateLimiter.record(clientIP)

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		logBreakglassAttempt(c.Request.Context(), clientIP, false, "invalid_request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
		return
	}

	// Verify password against bcrypt hash
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
	if err != nil {
		logBreakglassAttempt(c.Request.Context(), clientIP, false, "invalid_password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Determine tenant_id: use env var or first tenant in DB
	tenantID := os.Getenv("ZOVARK_BREAKGLASS_TENANT_ID")
	if tenantID == "" && dbPool != nil {
		err := dbPool.QueryRow(c.Request.Context(),
			`SELECT id FROM tenants WHERE is_active = true ORDER BY created_at LIMIT 1`,
		).Scan(&tenantID)
		if err != nil {
			log.Printf("[BREAKGLASS] No active tenants found: %v", err)
			tenantID = "00000000-0000-0000-0000-000000000000"
		}
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000000"
	}

	// Generate 15-minute JWT
	claims := CustomClaims{
		TenantID: tenantID,
		UserID:   "breakglass",
		Email:    "breakglass@zovark.local",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "access",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(appConfig.JWTSecret))
	if err != nil {
		logBreakglassAttempt(c.Request.Context(), clientIP, false, fmt.Sprintf("jwt_error: %v", err))
		respondInternalError(c, err, "generate breakglass token")
		return
	}

	logBreakglassAttempt(c.Request.Context(), clientIP, true, fmt.Sprintf("tenant=%s", tenantID))

	log.Printf("[BREAKGLASS] Successful login from %s for tenant %s", clientIP, tenantID)

	c.JSON(http.StatusOK, gin.H{
		"token":     tokenString,
		"expires_in": 900, // 15 minutes in seconds
		"user": map[string]interface{}{
			"id":        "breakglass",
			"email":     "breakglass@zovark.local",
			"role":      "admin",
			"tenant_id": tenantID,
		},
		"warning": "Break-glass session. All actions are audited. Token expires in 15 minutes.",
	})
}
