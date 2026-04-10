package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// enforceAdminDiagnosticRateLimit limits expensive admin diagnostic endpoints to 6 req/min per user (Valkey/Redis).
func enforceAdminDiagnosticRateLimit(c *gin.Context) bool {
	userID, ok := c.Get("user_id")
	if !ok {
		return true
	}
	uid, _ := userID.(string)
	if uid == "" {
		return true
	}
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	endpoint := "admin_diag:" + path

	var allowed bool
	if redisClient == nil {
		allowed = localRateCheck("rl:"+uid+":"+endpoint, 6, time.Minute)
	} else {
		_, allowed, _ = slidingWindowIncrement(uid, endpoint, 60, 6)
	}
	if !allowed {
		c.Header("Retry-After", "60")
		respondError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
			"Diagnostic endpoint rate limit exceeded (6 requests per minute).")
		return false
	}
	return true
}
