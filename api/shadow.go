package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================
// SHADOW MODE ENDPOINTS (Sprint v0.10.0)
// ============================================================

// GET /api/v1/shadow/recommendations — list pending recommendations for tenant
func listShadowRecommendationsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Parse pagination
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "20")
	status := c.Query("status")

	page := 1
	limit := 20
	if v, err := fmt.Sscanf(pageStr, "%d", &page); v == 0 || err != nil || page < 1 {
		page = 1
	}
	if v, err := fmt.Sscanf(limitStr, "%d", &limit); v == 0 || err != nil || limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Build query with optional status filter
	where := "WHERE sr.tenant_id = $1"
	args := []interface{}{tenantID}
	argN := 2

	if status != "" {
		where += fmt.Sprintf(" AND sr.status = $%d", argN)
		args = append(args, status)
		argN++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM shadow_recommendations sr " + where
	err := dbPool.QueryRow(c.Request.Context(), countQuery, args...).Scan(&total)
	if err != nil {
		log.Printf("Error counting shadow recommendations: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count recommendations"})
		return
	}

	// Fetch page
	dataArgs := make([]interface{}, len(args))
	copy(dataArgs, args)
	dataArgs = append(dataArgs, limit, offset)

	query := fmt.Sprintf(`
		SELECT sr.id, sr.task_id, sr.alert_id, sr.recommended_action, sr.severity,
		       sr.confidence_score, sr.reasoning, sr.status, sr.created_at, sr.decided_at,
		       sr.human_action, sr.match_category
		FROM shadow_recommendations sr %s
		ORDER BY sr.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)

	rows, err := dbPool.Query(c.Request.Context(), query, dataArgs...)
	if err != nil {
		log.Printf("Error querying shadow recommendations: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query recommendations"})
		return
	}
	defer rows.Close()

	var recommendations []map[string]interface{}
	for rows.Next() {
		var id, recommendedAction, severity, status string
		var taskID, alertID, reasoning, humanAction, matchCategory *string
		var confidenceScore float64
		var createdAt time.Time
		var decidedAt *time.Time

		if err := rows.Scan(&id, &taskID, &alertID, &recommendedAction, &severity,
			&confidenceScore, &reasoning, &status, &createdAt, &decidedAt,
			&humanAction, &matchCategory); err != nil {
			log.Printf("Error scanning shadow recommendation row: %v", err)
			continue
		}

		rec := map[string]interface{}{
			"id":                 id,
			"task_id":            taskID,
			"alert_id":          alertID,
			"recommended_action": recommendedAction,
			"severity":           severity,
			"confidence_score":   confidenceScore,
			"reasoning":          reasoning,
			"status":             status,
			"created_at":         createdAt,
			"decided_at":         decidedAt,
			"human_action":       humanAction,
			"match_category":     matchCategory,
		}
		recommendations = append(recommendations, rec)
	}

	if recommendations == nil {
		recommendations = []map[string]interface{}{}
	}

	pages := (total + limit - 1) / limit

	c.JSON(http.StatusOK, gin.H{
		"recommendations": recommendations,
		"total":           total,
		"page":            page,
		"limit":           limit,
		"pages":           pages,
	})
}

// GET /api/v1/shadow/recommendations/:id — get single recommendation detail
func getShadowRecommendationHandler(c *gin.Context) {
	recID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	var id, recommendedAction, severity, status string
	var taskID, alertID, reasoning, humanAction, humanReasoning, matchCategory *string
	var confidenceScore float64
	var createdAt time.Time
	var decidedAt *time.Time
	var decidedBy *string
	var contextData *json.RawMessage

	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT sr.id, sr.task_id, sr.alert_id, sr.recommended_action, sr.severity,
		       sr.confidence_score, sr.reasoning, sr.status, sr.created_at, sr.decided_at,
		       sr.decided_by, sr.human_action, sr.human_reasoning, sr.match_category,
		       sr.context_data
		FROM shadow_recommendations sr
		WHERE sr.id = $1 AND sr.tenant_id = $2
	`, recID, tenantID).Scan(&id, &taskID, &alertID, &recommendedAction, &severity,
		&confidenceScore, &reasoning, &status, &createdAt, &decidedAt,
		&decidedBy, &humanAction, &humanReasoning, &matchCategory,
		&contextData)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recommendation not found"})
		return
	}

	rec := map[string]interface{}{
		"id":                 id,
		"task_id":            taskID,
		"alert_id":          alertID,
		"recommended_action": recommendedAction,
		"severity":           severity,
		"confidence_score":   confidenceScore,
		"reasoning":          reasoning,
		"status":             status,
		"created_at":         createdAt,
		"decided_at":         decidedAt,
		"decided_by":         decidedBy,
		"human_action":       humanAction,
		"human_reasoning":    humanReasoning,
		"match_category":     matchCategory,
		"context_data":       contextData,
	}

	c.JSON(http.StatusOK, gin.H{"recommendation": rec})
}

// POST /api/v1/shadow/recommendations/:id/decide — human decision on recommendation
func decideShadowRecommendationHandler(c *gin.Context) {
	recID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Action        string `json:"action" binding:"required"`
		Severity      string `json:"severity"`
		Reasoning     string `json:"reasoning" binding:"required"`
		MatchCategory string `json:"match_category" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate match_category
	validCategories := map[string]bool{
		"exact_match":   true,
		"partial_match": true,
		"override":      true,
		"rejection":     true,
	}
	if !validCategories[req.MatchCategory] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid match_category; must be exact_match, partial_match, override, or rejection"})
		return
	}

	// Verify the recommendation exists, belongs to tenant, and is pending
	var currentStatus string
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT status FROM shadow_recommendations WHERE id = $1 AND tenant_id = $2",
		recID, tenantID,
	).Scan(&currentStatus)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recommendation not found"})
		return
	}
	if currentStatus != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "recommendation already decided"})
		return
	}

	// Update the recommendation with human decision
	_, err = dbPool.Exec(c.Request.Context(), `
		UPDATE shadow_recommendations
		SET status = 'decided',
		    decided_at = NOW(),
		    decided_by = $1,
		    human_action = $2,
		    human_reasoning = $3,
		    match_category = $4
		WHERE id = $5 AND tenant_id = $6
	`, userID, req.Action, req.Reasoning, req.MatchCategory, recID, tenantID)
	if err != nil {
		log.Printf("Error updating shadow recommendation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update recommendation"})
		return
	}

	// Record in conformance log for analytics
	_, _ = dbPool.Exec(c.Request.Context(), `
		INSERT INTO shadow_conformance_log (id, tenant_id, recommendation_id, match_category, decided_by)
		VALUES ($1, $2, $3, $4, $5)
	`, uuid.New().String(), tenantID, recID, req.MatchCategory, userID)

	// Audit log
	_, _ = dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, "shadow_recommendation_decided", "shadow_recommendation", recID,
		fmt.Sprintf(`{"action": "%s", "match_category": "%s", "decided_by": "%s"}`, req.Action, req.MatchCategory, userID),
	)

	c.JSON(http.StatusOK, gin.H{
		"status":            "decided",
		"recommendation_id": recID,
		"match_category":    req.MatchCategory,
		"human_action":      req.Action,
	})
}

// GET /api/v1/shadow/conformance — conformance stats for tenant
func getShadowConformanceHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Get match category distribution
	var totalDecisions, exactMatches, partialMatches, overrides, rejections int
	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*) as total,
			COALESCE(COUNT(*) FILTER (WHERE match_category = 'exact_match'), 0),
			COALESCE(COUNT(*) FILTER (WHERE match_category = 'partial_match'), 0),
			COALESCE(COUNT(*) FILTER (WHERE match_category = 'override'), 0),
			COALESCE(COUNT(*) FILTER (WHERE match_category = 'rejection'), 0)
		FROM shadow_recommendations
		WHERE tenant_id = $1 AND status = 'decided'
	`, tenantID).Scan(&totalDecisions, &exactMatches, &partialMatches, &overrides, &rejections)
	if err != nil {
		log.Printf("Error querying conformance stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query conformance stats"})
		return
	}

	// Calculate rates
	var exactMatchRate, partialMatchRate, overrideRate, rejectionRate float64
	if totalDecisions > 0 {
		exactMatchRate = float64(exactMatches) / float64(totalDecisions) * 100
		partialMatchRate = float64(partialMatches) / float64(totalDecisions) * 100
		overrideRate = float64(overrides) / float64(totalDecisions) * 100
		rejectionRate = float64(rejections) / float64(totalDecisions) * 100
	}

	// Combined match rate (exact + partial = agreement)
	combinedMatchRate := exactMatchRate + partialMatchRate

	// Pending recommendations count
	var pendingCount int
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*) FROM shadow_recommendations WHERE tenant_id = $1 AND status = 'pending'",
		tenantID,
	).Scan(&pendingCount)

	// Last 7 days trend (daily conformance)
	trendRows, err := dbPool.Query(c.Request.Context(), `
		SELECT DATE(decided_at) as day,
		       COUNT(*) as total,
		       COUNT(*) FILTER (WHERE match_category IN ('exact_match', 'partial_match')) as matches
		FROM shadow_recommendations
		WHERE tenant_id = $1 AND status = 'decided' AND decided_at > NOW() - INTERVAL '7 days'
		GROUP BY DATE(decided_at)
		ORDER BY day ASC
	`, tenantID)

	var dailyTrend []map[string]interface{}
	if err == nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var day time.Time
			var dayTotal, dayMatches int
			if err := trendRows.Scan(&day, &dayTotal, &dayMatches); err != nil {
				continue
			}
			rate := float64(0)
			if dayTotal > 0 {
				rate = float64(dayMatches) / float64(dayTotal) * 100
			}
			dailyTrend = append(dailyTrend, map[string]interface{}{
				"date":       day.Format("2006-01-02"),
				"total":      dayTotal,
				"matches":    dayMatches,
				"match_rate": rate,
			})
		}
	}
	if dailyTrend == nil {
		dailyTrend = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_decisions":      totalDecisions,
		"exact_matches":        exactMatches,
		"partial_matches":      partialMatches,
		"overrides":            overrides,
		"rejections":           rejections,
		"exact_match_rate":     exactMatchRate,
		"partial_match_rate":   partialMatchRate,
		"override_rate":        overrideRate,
		"rejection_rate":       rejectionRate,
		"combined_match_rate":  combinedMatchRate,
		"pending_count":        pendingCount,
		"daily_trend":          dailyTrend,
	})
}

// GET /api/v1/shadow/status — shadow mode status for tenant
func getShadowStatusHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Get shadow mode configuration from tenant settings
	var settings map[string]interface{}
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT COALESCE(settings, '{}') FROM tenants WHERE id = $1", tenantID,
	).Scan(&settings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query tenant settings"})
		return
	}

	// Extract shadow mode settings
	shadowMode := "shadow" // default
	if mode, ok := settings["automation_mode"].(string); ok {
		shadowMode = mode
	}

	shadowStartDate := time.Time{}
	if startStr, ok := settings["shadow_start_date"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, startStr); err == nil {
			shadowStartDate = parsed
		}
	}

	dayCount := 0
	if !shadowStartDate.IsZero() {
		dayCount = int(time.Since(shadowStartDate).Hours() / 24)
	}

	// Promotion threshold from settings (default 90%)
	promotionThreshold := float64(90)
	if thresh, ok := settings["shadow_promotion_threshold"].(float64); ok {
		promotionThreshold = thresh
	}

	// Current match rate
	var totalDecisions, matchCount int
	_ = dbPool.QueryRow(c.Request.Context(), `
		SELECT
			COALESCE(COUNT(*), 0),
			COALESCE(COUNT(*) FILTER (WHERE match_category IN ('exact_match', 'partial_match')), 0)
		FROM shadow_recommendations
		WHERE tenant_id = $1 AND status = 'decided'
	`, tenantID).Scan(&totalDecisions, &matchCount)

	matchRate := float64(0)
	if totalDecisions > 0 {
		matchRate = float64(matchCount) / float64(totalDecisions) * 100
	}

	// Eligible for promotion?
	eligible := dayCount >= 14 && matchRate >= promotionThreshold && totalDecisions >= 50

	c.JSON(http.StatusOK, gin.H{
		"mode":                shadowMode,
		"day_count":           dayCount,
		"shadow_start_date":   shadowStartDate,
		"match_rate":          matchRate,
		"total_decisions":     totalDecisions,
		"promotion_threshold": promotionThreshold,
		"promotion_eligible":  eligible,
		"requirements": gin.H{
			"min_days":               14,
			"min_match_rate":         promotionThreshold,
			"min_decisions":          50,
			"days_met":               dayCount >= 14,
			"match_rate_met":         matchRate >= promotionThreshold,
			"decisions_met":          totalDecisions >= 50,
		},
	})
}
