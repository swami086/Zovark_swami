package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// PER-TENANT API RATE LIMITING WITH REDIS (Issue #11)
// ============================================================

var redisAddr string

func initRedis() {
	redisAddr = getEnvOrDefault("REDIS_URL", "redis:6379")
	// Strip redis:// prefix if present
	if len(redisAddr) > 8 && redisAddr[:8] == "redis://" {
		redisAddr = redisAddr[8:]
	}
}

// redisCommand sends a raw Redis command via TCP and returns the response.
// This is a minimal Redis client using the RESP protocol to avoid external deps.
func redisCommand(args ...string) (string, error) {
	conn, err := net.DialTimeout("tcp", redisAddr, 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("redis connect: %w", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Build RESP array
	cmd := fmt.Sprintf("*%d\r\n", len(args))
	for _, arg := range args {
		cmd += fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)
	}

	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return "", fmt.Errorf("redis write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("redis read: %w", err)
	}

	return string(buf[:n]), nil
}

// parseRedisInt parses an integer response from Redis RESP protocol.
func parseRedisInt(resp string) (int, error) {
	if len(resp) > 0 && resp[0] == ':' {
		// Integer reply ":N\r\n"
		end := len(resp)
		for i := 1; i < len(resp); i++ {
			if resp[i] == '\r' || resp[i] == '\n' {
				end = i
				break
			}
		}
		return strconv.Atoi(resp[1:end])
	}
	return 0, fmt.Errorf("unexpected redis response: %s", resp)
}

// slidingWindowIncrement implements a Redis-based sliding window rate limiter.
// Returns (current count, allowed, error).
func slidingWindowIncrement(tenantID, endpoint string, windowSeconds, limit int) (int, bool, error) {
	now := time.Now().Unix()
	windowStart := now - int64(windowSeconds)
	key := fmt.Sprintf("ratelimit:%s:%s:%d", tenantID, endpoint, windowSeconds)
	member := fmt.Sprintf("%d:%d", now, time.Now().UnixNano())

	// ZADD key now member
	_, err := redisCommand("ZADD", key, fmt.Sprintf("%d", now), member)
	if err != nil {
		return 0, true, err // Allow on Redis failure
	}

	// ZREMRANGEBYSCORE key -inf windowStart
	_, _ = redisCommand("ZREMRANGEBYSCORE", key, "-inf", fmt.Sprintf("%d", windowStart))

	// ZCARD key
	resp, err := redisCommand("ZCARD", key)
	if err != nil {
		return 0, true, err
	}

	count, err := parseRedisInt(resp)
	if err != nil {
		return 0, true, err
	}

	// Set TTL on the key
	_, _ = redisCommand("EXPIRE", key, fmt.Sprintf("%d", windowSeconds+10))

	return count, count <= limit, nil
}

// getTenantRateLimits reads per-tenant rate limit overrides from settings JSONB.
func getTenantRateLimits(ctx context.Context, tenantID string) (perMinute int, perHour int) {
	perMinute = 100  // Default: 100 req/min
	perHour = 1000   // Default: 1000 req/hour

	var settings map[string]interface{}
	err := dbPool.QueryRow(ctx,
		"SELECT settings FROM tenants WHERE id = $1", tenantID,
	).Scan(&settings)
	if err != nil {
		return perMinute, perHour
	}

	if rl, ok := settings["rate_limit_per_minute"]; ok {
		if v, ok := rl.(float64); ok {
			perMinute = int(v)
		}
	}
	if rl, ok := settings["rate_limit_per_hour"]; ok {
		if v, ok := rl.(float64); ok {
			perHour = int(v)
		}
	}

	return perMinute, perHour
}

// tenantRateLimitMiddleware enforces per-tenant rate limiting using Redis sliding windows.
func tenantRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.Next()
			return
		}

		tid := tenantID.(string)
		endpoint := c.FullPath()
		if endpoint == "" {
			endpoint = c.Request.URL.Path
		}

		perMinute, perHour := getTenantRateLimits(c.Request.Context(), tid)

		// Check per-minute limit
		countMin, allowedMin, err := slidingWindowIncrement(tid, endpoint, 60, perMinute)
		if err != nil {
			log.Printf("Rate limit Redis error (minute): %v", err)
			// Allow request on Redis failure (fail-open)
			c.Next()
			return
		}

		if !allowedMin {
			retryAfter := 60 - (time.Now().Unix() % 60)
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perMinute))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()+retryAfter))
			respondError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
				fmt.Sprintf("Rate limit exceeded: %d requests per minute. Retry after %d seconds.", perMinute, retryAfter))
			c.Abort()
			return
		}

		// Check per-hour limit
		countHour, allowedHour, err := slidingWindowIncrement(tid, endpoint, 3600, perHour)
		if err != nil {
			log.Printf("Rate limit Redis error (hour): %v", err)
			c.Next()
			return
		}

		if !allowedHour {
			retryAfter := 3600 - (time.Now().Unix() % 3600)
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perHour))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()+retryAfter))
			respondError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
				fmt.Sprintf("Rate limit exceeded: %d requests per hour. Retry after %d seconds.", perHour, retryAfter))
			c.Abort()
			return
		}

		// Set rate limit headers
		remainingMin := perMinute - countMin
		if remainingMin < 0 {
			remainingMin = 0
		}
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", perMinute))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remainingMin))

		_ = countHour // Used in the check above

		c.Next()
	}
}
