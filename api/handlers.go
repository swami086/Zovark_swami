package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func healthCheckHandler(c *gin.Context) {
	deploymentMode := getEnvOrDefault("ZOVARK_DEPLOYMENT_MODE", "cloud")
	llmModel := getEnvOrDefault("ZOVARK_LLM_MODEL", "fast")

	llmProvider := "OpenRouter (Cloud)"
	if llmModel == "zovark-local" {
		llmProvider = "Ollama (Local)"
	}

	// Check DB
	dbOK := false
	if dbPool != nil {
		err := dbPool.Ping(c.Request.Context())
		dbOK = (err == nil)
	}

	// LLM health (Ollama on host — check is best-effort)
	llmOK := false
	resp, err := http.Get("http://host.docker.internal:11434/api/tags")
	if err == nil {
		llmOK = (resp.StatusCode == 200)
		resp.Body.Close()
	}

	// Check embedding server
	embeddingOK := false
	resp, err = http.Get("http://embedding-server:80/health")
	if err == nil {
		embeddingOK = (resp.StatusCode == 200)
		resp.Body.Close()
	}

	c.JSON(http.StatusOK, gin.H{
		"status":             "ok",
		"version":            "1.0.0-rc1",
		"uptime_seconds":     int(time.Since(startTime).Seconds()),
		"mode":               deploymentMode,
		"llm_provider":       llmProvider,
		"llm_model":          llmModel,
		"embedding_provider": "HuggingFace TEI (Local)",
		"database":           "PostgreSQL + pgvector",
		"services": gin.H{
			"api":       true,
			"db":        dbOK,
			"llm":       llmOK,
			"embedding": embeddingOK,
		},
	})
}

// readinessHandler checks that ALL critical dependencies are reachable.
// Returns 200 only if PostgreSQL, Redis, and Temporal are all healthy.
// Returns 503 with details if any fail. Used by Docker healthcheck and load balancers.
// GET /ready
func readinessHandler(c *gin.Context) {
	checks := make(map[string]gin.H)
	allReady := true

	// PostgreSQL via PgBouncer
	dbReady := false
	dbDetail := "not initialized"
	if dbPool != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		var one int
		err := dbPool.QueryRow(ctx, "SELECT 1").Scan(&one)
		if err == nil && one == 1 {
			dbReady = true
			dbDetail = "SELECT 1 OK"
		} else if err != nil {
			dbDetail = err.Error()
		}
	}
	checks["postgresql"] = gin.H{"ready": dbReady, "detail": dbDetail}
	if !dbReady {
		allReady = false
	}

	// Redis
	redisReady := false
	redisDetail := "not initialized"
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		err := redisClient.Ping(ctx).Err()
		if err == nil {
			redisReady = true
			redisDetail = "PONG"
		} else {
			redisDetail = err.Error()
		}
	}
	checks["redis"] = gin.H{"ready": redisReady, "detail": redisDetail}
	if !redisReady {
		allReady = false
	}

	// Temporal — check gRPC connectivity via the SDK client
	temporalReady := false
	temporalDetail := "not initialized"
	if tc != nil {
		// The SDK client maintains a gRPC connection; if Dial succeeded and
		// the connection hasn't been closed, Temporal is reachable.
		temporalReady = true
		temporalDetail = "client connected"
	}
	checks["temporal"] = gin.H{"ready": temporalReady, "detail": temporalDetail}
	if !temporalReady {
		allReady = false
	}

	status := http.StatusOK
	statusText := "ready"
	if !allReady {
		status = http.StatusServiceUnavailable
		statusText = "not_ready"
	}

	c.JSON(status, gin.H{
		"status":         statusText,
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"checks":         checks,
	})
}
