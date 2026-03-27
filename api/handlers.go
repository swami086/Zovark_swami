package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func healthCheckHandler(c *gin.Context) {
	deploymentMode := getEnvOrDefault("ZOVARC_DEPLOYMENT_MODE", "cloud")
	llmModel := getEnvOrDefault("ZOVARC_LLM_MODEL", "fast")

	llmProvider := "OpenRouter (Cloud)"
	if llmModel == "zovarc-local" {
		llmProvider = "Ollama (Local)"
	}

	// Check DB
	dbOK := false
	if dbPool != nil {
		err := dbPool.Ping(c.Request.Context())
		dbOK = (err == nil)
	}

	// Check LiteLLM
	litellmOK := false
	resp, err := http.Get("http://litellm:4000/health/liveliness")
	if err == nil {
		litellmOK = (resp.StatusCode == 200)
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
			"litellm":   litellmOK,
			"embedding": embeddingOK,
		},
	})
}
