package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================
// MODEL REGISTRY CRUD
// ============================================================

func listModelsHandler(c *gin.Context) {
	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, name, provider, model_id, version, status, is_default, config, routing_rules, eval_score, created_at FROM model_registry ORDER BY created_at DESC",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query models"})
		return
	}
	defer rows.Close()

	var models []map[string]interface{}
	for rows.Next() {
		var id, name, provider, modelID, version, status string
		var isDefault bool
		var config, routingRules map[string]interface{}
		var evalScore *float64
		var createdAt time.Time

		if err := rows.Scan(&id, &name, &provider, &modelID, &version, &status, &isDefault, &config, &routingRules, &evalScore, &createdAt); err != nil {
			log.Printf("Error scanning model row: %v", err)
			continue
		}

		models = append(models, map[string]interface{}{
			"id":            id,
			"name":          name,
			"provider":      provider,
			"model_id":      modelID,
			"version":       version,
			"status":        status,
			"is_default":    isDefault,
			"config":        config,
			"routing_rules": routingRules,
			"eval_score":    evalScore,
			"created_at":    createdAt,
		})
	}

	if models == nil {
		models = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"models": models, "count": len(models)})
}

func createModelHandler(c *gin.Context) {
	var req struct {
		Name         string                 `json:"name" binding:"required"`
		Provider     string                 `json:"provider" binding:"required"`
		ModelID      string                 `json:"model_id" binding:"required"`
		Version      string                 `json:"version"`
		IsDefault    bool                   `json:"is_default"`
		Config       map[string]interface{} `json:"config"`
		RoutingRules map[string]interface{} `json:"routing_rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Version == "" {
		req.Version = "1.0"
	}
	if req.Config == nil {
		req.Config = map[string]interface{}{}
	}
	if req.RoutingRules == nil {
		req.RoutingRules = map[string]interface{}{}
	}

	id := uuid.New().String()
	configJSON, _ := json.Marshal(req.Config)
	rulesJSON, _ := json.Marshal(req.RoutingRules)

	// If setting as default, clear existing default
	if req.IsDefault {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET is_default = false WHERE is_default = true")
	}

	_, err := dbPool.Exec(c.Request.Context(),
		"INSERT INTO model_registry (id, name, provider, model_id, version, is_default, config, routing_rules) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		id, req.Name, req.Provider, req.ModelID, req.Version, req.IsDefault, configJSON, rulesJSON,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create model"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":         id,
		"name":       req.Name,
		"provider":   req.Provider,
		"model_id":   req.ModelID,
		"version":    req.Version,
		"is_default": req.IsDefault,
	})
}

func updateModelHandler(c *gin.Context) {
	modelID := c.Param("id")

	var req struct {
		Name         *string                `json:"name"`
		Status       *string                `json:"status"`
		IsDefault    *bool                  `json:"is_default"`
		Config       map[string]interface{} `json:"config"`
		RoutingRules map[string]interface{} `json:"routing_rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var exists bool
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM model_registry WHERE id = $1)", modelID,
	).Scan(&exists)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "model not found"})
		return
	}

	if req.Name != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET name = $1, updated_at = NOW() WHERE id = $2", *req.Name, modelID)
	}
	if req.Status != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET status = $1, updated_at = NOW() WHERE id = $2", *req.Status, modelID)
	}
	if req.IsDefault != nil && *req.IsDefault {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET is_default = false WHERE is_default = true")
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET is_default = true, status = 'promoted', updated_at = NOW() WHERE id = $1", modelID)
	}
	if req.Config != nil {
		configJSON, _ := json.Marshal(req.Config)
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET config = $1, updated_at = NOW() WHERE id = $2", configJSON, modelID)
	}
	if req.RoutingRules != nil {
		rulesJSON, _ := json.Marshal(req.RoutingRules)
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET routing_rules = $1, updated_at = NOW() WHERE id = $2", rulesJSON, modelID)
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ============================================================
// A/B TESTING
// ============================================================

func listABTestsHandler(c *gin.Context) {
	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT ab.id, ab.name, ab.traffic_split, ab.status,
		       ma.name as model_a_name, mb.name as model_b_name,
		       ab.results_a, ab.results_b, ab.winner_id, ab.started_at, ab.completed_at
		FROM model_ab_tests ab
		JOIN model_registry ma ON ab.model_a_id = ma.id
		JOIN model_registry mb ON ab.model_b_id = mb.id
		ORDER BY ab.started_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query A/B tests"})
		return
	}
	defer rows.Close()

	var tests []map[string]interface{}
	for rows.Next() {
		var id, name, status, modelAName, modelBName string
		var trafficSplit float64
		var resultsA, resultsB map[string]interface{}
		var winnerID *string
		var startedAt time.Time
		var completedAt *time.Time

		if err := rows.Scan(&id, &name, &trafficSplit, &status, &modelAName, &modelBName, &resultsA, &resultsB, &winnerID, &startedAt, &completedAt); err != nil {
			log.Printf("Error scanning A/B test: %v", err)
			continue
		}

		tests = append(tests, map[string]interface{}{
			"id":            id,
			"name":          name,
			"traffic_split": trafficSplit,
			"status":        status,
			"model_a":       modelAName,
			"model_b":       modelBName,
			"results_a":     resultsA,
			"results_b":     resultsB,
			"winner_id":     winnerID,
			"started_at":    startedAt,
			"completed_at":  completedAt,
		})
	}

	if tests == nil {
		tests = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"ab_tests": tests, "count": len(tests)})
}

func createABTestHandler(c *gin.Context) {
	var req struct {
		Name         string  `json:"name" binding:"required"`
		ModelAID     string  `json:"model_a_id" binding:"required"`
		ModelBID     string  `json:"model_b_id" binding:"required"`
		TrafficSplit float64 `json:"traffic_split"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.TrafficSplit <= 0 || req.TrafficSplit >= 1 {
		req.TrafficSplit = 0.5
	}

	id := uuid.New().String()
	_, err := dbPool.Exec(c.Request.Context(),
		"INSERT INTO model_ab_tests (id, name, model_a_id, model_b_id, traffic_split) VALUES ($1, $2, $3, $4, $5)",
		id, req.Name, req.ModelAID, req.ModelBID, req.TrafficSplit,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create A/B test"})
		return
	}

	// Mark both models as testing
	_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET status = 'testing' WHERE id IN ($1, $2)", req.ModelAID, req.ModelBID)

	c.JSON(http.StatusCreated, gin.H{
		"id":            id,
		"name":          req.Name,
		"traffic_split": req.TrafficSplit,
		"status":        "running",
	})
}

func completeABTestHandler(c *gin.Context) {
	testID := c.Param("id")

	var req struct {
		WinnerID string `json:"winner_id" binding:"required"`
		Promote  bool   `json:"promote"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := dbPool.Exec(c.Request.Context(),
		"UPDATE model_ab_tests SET status = 'completed', winner_id = $1, completed_at = NOW() WHERE id = $2",
		req.WinnerID, testID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete A/B test"})
		return
	}

	if req.Promote {
		// Promote winner to default
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET is_default = false WHERE is_default = true")
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE model_registry SET is_default = true, status = 'promoted', updated_at = NOW() WHERE id = $1", req.WinnerID)
	}

	c.JSON(http.StatusOK, gin.H{"status": "completed", "winner_id": req.WinnerID, "promoted": req.Promote})
}
