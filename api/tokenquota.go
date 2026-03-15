package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// TOKEN QUOTA ENDPOINTS (Sprint v0.10.0)
// ============================================================

// GET /api/v1/quotas — get current tenant quota status
func getTokenQuotaHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var monthlyTokenLimit, monthlyTokensUsed int64
	var monthlyCostLimitUSD, monthlyCostUsedUSD float64
	var warnThresholdPct int
	var circuitBreakerOpen bool
	var circuitBreakerReason *string
	var circuitBreakerOpenedAt *time.Time
	var updatedAt time.Time

	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT monthly_token_limit, monthly_tokens_used,
		       monthly_cost_limit_usd, monthly_cost_used_usd,
		       warn_threshold_pct, circuit_breaker_open,
		       circuit_breaker_reason, circuit_breaker_opened_at,
		       updated_at
		FROM token_quotas
		WHERE tenant_id = $1
	`, tenantID).Scan(
		&monthlyTokenLimit, &monthlyTokensUsed,
		&monthlyCostLimitUSD, &monthlyCostUsedUSD,
		&warnThresholdPct, &circuitBreakerOpen,
		&circuitBreakerReason, &circuitBreakerOpenedAt,
		&updatedAt,
	)

	if err != nil {
		// No quota configured — return defaults
		c.JSON(http.StatusOK, gin.H{
			"tenant_id":              tenantID,
			"monthly_token_limit":    0,
			"monthly_tokens_used":    0,
			"monthly_cost_limit_usd": 0,
			"monthly_cost_used_usd":  0,
			"warn_threshold_pct":     80,
			"token_usage_pct":        0,
			"cost_usage_pct":         0,
			"circuit_breaker_open":   false,
			"configured":             false,
		})
		return
	}

	// Calculate usage percentages
	tokenUsagePct := float64(0)
	if monthlyTokenLimit > 0 {
		tokenUsagePct = float64(monthlyTokensUsed) / float64(monthlyTokenLimit) * 100
	}
	costUsagePct := float64(0)
	if monthlyCostLimitUSD > 0 {
		costUsagePct = monthlyCostUsedUSD / monthlyCostLimitUSD * 100
	}

	// Determine warning status
	warning := false
	if tokenUsagePct >= float64(warnThresholdPct) || costUsagePct >= float64(warnThresholdPct) {
		warning = true
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id":                 tenantID,
		"monthly_token_limit":       monthlyTokenLimit,
		"monthly_tokens_used":       monthlyTokensUsed,
		"monthly_cost_limit_usd":    monthlyCostLimitUSD,
		"monthly_cost_used_usd":     monthlyCostUsedUSD,
		"warn_threshold_pct":        warnThresholdPct,
		"token_usage_pct":           tokenUsagePct,
		"cost_usage_pct":            costUsagePct,
		"circuit_breaker_open":      circuitBreakerOpen,
		"circuit_breaker_reason":    circuitBreakerReason,
		"circuit_breaker_opened_at": circuitBreakerOpenedAt,
		"warning":                   warning,
		"configured":                true,
		"updated_at":                updatedAt,
	})
}

// PUT /api/v1/quotas — update tenant quota limits (admin only)
func updateTokenQuotaHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		MonthlyTokenLimit  *int64   `json:"monthly_token_limit"`
		MonthlyCostLimitUSD *float64 `json:"monthly_cost_limit_usd"`
		WarnThresholdPct   *int     `json:"warn_threshold_pct"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate warn_threshold_pct range
	if req.WarnThresholdPct != nil && (*req.WarnThresholdPct < 1 || *req.WarnThresholdPct > 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "warn_threshold_pct must be between 1 and 100"})
		return
	}

	// Defaults for upsert
	tokenLimit := int64(10000000)
	if req.MonthlyTokenLimit != nil {
		tokenLimit = *req.MonthlyTokenLimit
	}
	costLimit := float64(500.00)
	if req.MonthlyCostLimitUSD != nil {
		costLimit = *req.MonthlyCostLimitUSD
	}
	warnPct := 80
	if req.WarnThresholdPct != nil {
		warnPct = *req.WarnThresholdPct
	}

	// Upsert token quota
	_, err := dbPool.Exec(c.Request.Context(), `
		INSERT INTO token_quotas (tenant_id, monthly_token_limit, monthly_cost_limit_usd, warn_threshold_pct)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id)
		DO UPDATE SET
			monthly_token_limit = COALESCE($2, token_quotas.monthly_token_limit),
			monthly_cost_limit_usd = COALESCE($3, token_quotas.monthly_cost_limit_usd),
			warn_threshold_pct = COALESCE($4, token_quotas.warn_threshold_pct),
			updated_at = NOW()
	`, tenantID, tokenLimit, costLimit, warnPct)

	if err != nil {
		respondInternalError(c, err, "update token quota")
		return
	}

	// Audit log
	_, _ = dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, "quota_updated", "token_quota", tenantID,
		func() string { d, _ := json.Marshal(map[string]interface{}{"token_limit": tokenLimit, "cost_limit": costLimit, "warn_pct": warnPct, "updated_by": userID}); return string(d) }(),
	)

	c.JSON(http.StatusOK, gin.H{
		"status":               "updated",
		"monthly_token_limit":  tokenLimit,
		"monthly_cost_limit_usd": costLimit,
		"warn_threshold_pct":   warnPct,
	})
}

// POST /api/v1/quotas/circuit-breaker — open/close circuit breaker (admin only)
func circuitBreakerHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Open   bool   `json:"open"`
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()

	if req.Open {
		// Open circuit breaker — block all LLM calls
		_, err := dbPool.Exec(c.Request.Context(), `
			INSERT INTO token_quotas (tenant_id, circuit_breaker_open, circuit_breaker_reason, circuit_breaker_opened_at)
			VALUES ($1, true, $2, $3)
			ON CONFLICT (tenant_id)
			DO UPDATE SET circuit_breaker_open = true, circuit_breaker_reason = $2, circuit_breaker_opened_at = $3, updated_at = NOW()
		`, tenantID, req.Reason, now)
		if err != nil {
			respondInternalError(c, err, "open circuit breaker")
			return
		}
	} else {
		// Close circuit breaker — resume LLM calls
		_, err := dbPool.Exec(c.Request.Context(), `
			UPDATE token_quotas
			SET circuit_breaker_open = false, circuit_breaker_reason = NULL, circuit_breaker_opened_at = NULL, updated_at = NOW()
			WHERE tenant_id = $1
		`, tenantID)
		if err != nil {
			respondInternalError(c, err, "close circuit breaker")
			return
		}
	}

	// Audit log
	action := "circuit_breaker_opened"
	if !req.Open {
		action = "circuit_breaker_closed"
	}
	_, _ = dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, action, "token_quota", tenantID,
		func() string { d, _ := json.Marshal(map[string]interface{}{"open": req.Open, "reason": req.Reason, "performed_by": userID}); return string(d) }(),
	)

	// Dispatch webhook for circuit breaker state change
	go DispatchWebhook(tenantID, "circuit_breaker_changed", map[string]interface{}{
		"open":         req.Open,
		"reason":       req.Reason,
		"performed_by": userID,
		"timestamp":    now,
	})

	c.JSON(http.StatusOK, gin.H{
		"status":               action,
		"circuit_breaker_open": req.Open,
		"reason":               req.Reason,
	})
}

// GET /api/v1/quotas/usage — detailed usage breakdown
func getTokenUsageHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// By model breakdown
	modelRows, err := dbPool.Query(c.Request.Context(), `
		SELECT model_name,
		       COALESCE(SUM(tokens_input), 0) as tokens_in,
		       COALESCE(SUM(tokens_output), 0) as tokens_out,
		       COALESCE(SUM(cost_usd), 0) as cost,
		       COUNT(*) as call_count
		FROM llm_call_log
		WHERE tenant_id = $1
		  AND created_at >= DATE_TRUNC('month', CURRENT_DATE)
		GROUP BY model_name
		ORDER BY cost DESC
	`, tenantID)

	var byModel []map[string]interface{}
	if err == nil {
		defer modelRows.Close()
		for modelRows.Next() {
			var modelName string
			var tokensIn, tokensOut, callCount int64
			var cost float64

			if err := modelRows.Scan(&modelName, &tokensIn, &tokensOut, &cost, &callCount); err != nil {
				continue
			}

			byModel = append(byModel, map[string]interface{}{
				"model":        modelName,
				"tokens_input": tokensIn,
				"tokens_output": tokensOut,
				"total_tokens": tokensIn + tokensOut,
				"cost_usd":     cost,
				"call_count":   callCount,
			})
		}
	}
	if byModel == nil {
		byModel = []map[string]interface{}{}
	}

	// By day breakdown (current month)
	dayRows, err := dbPool.Query(c.Request.Context(), `
		SELECT DATE(created_at) as day,
		       COALESCE(SUM(tokens_input + tokens_output), 0) as total_tokens,
		       COALESCE(SUM(cost_usd), 0) as cost,
		       COUNT(*) as call_count
		FROM llm_call_log
		WHERE tenant_id = $1
		  AND created_at >= DATE_TRUNC('month', CURRENT_DATE)
		GROUP BY DATE(created_at)
		ORDER BY day ASC
	`, tenantID)

	var byDay []map[string]interface{}
	if err == nil {
		defer dayRows.Close()
		for dayRows.Next() {
			var day time.Time
			var totalTokens, callCount int64
			var cost float64

			if err := dayRows.Scan(&day, &totalTokens, &cost, &callCount); err != nil {
				continue
			}

			byDay = append(byDay, map[string]interface{}{
				"date":         day.Format("2006-01-02"),
				"total_tokens": totalTokens,
				"cost_usd":     cost,
				"call_count":   callCount,
			})
		}
	}
	if byDay == nil {
		byDay = []map[string]interface{}{}
	}

	// Summary totals for current month
	var totalTokens, totalCalls int64
	var totalCost float64
	_ = dbPool.QueryRow(c.Request.Context(), `
		SELECT COALESCE(SUM(tokens_input + tokens_output), 0),
		       COALESCE(SUM(cost_usd), 0),
		       COALESCE(COUNT(*), 0)
		FROM llm_call_log
		WHERE tenant_id = $1
		  AND created_at >= DATE_TRUNC('month', CURRENT_DATE)
	`, tenantID).Scan(&totalTokens, &totalCost, &totalCalls)

	c.JSON(http.StatusOK, gin.H{
		"period":       time.Now().Format("2006-01"),
		"total_tokens": totalTokens,
		"total_cost":   totalCost,
		"total_calls":  totalCalls,
		"by_model":     byModel,
		"by_day":       byDay,
	})
}

// checkTokenQuota is a middleware function called before any LLM-triggering endpoint.
// It checks the tenant's token quota and circuit breaker status.
func checkTokenQuota() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.Next()
			return
		}

		tid := tenantID.(string)

		var monthlyTokenLimit, monthlyTokensUsed int64
		var monthlyCostLimitUSD, monthlyCostUsedUSD float64
		var warnThresholdPct int
		var circuitBreakerOpen bool

		err := dbPool.QueryRow(c.Request.Context(), `
			SELECT monthly_token_limit, monthly_tokens_used,
			       monthly_cost_limit_usd, monthly_cost_used_usd,
			       warn_threshold_pct, circuit_breaker_open
			FROM token_quotas
			WHERE tenant_id = $1
		`, tid).Scan(
			&monthlyTokenLimit, &monthlyTokensUsed,
			&monthlyCostLimitUSD, &monthlyCostUsedUSD,
			&warnThresholdPct, &circuitBreakerOpen,
		)

		if err != nil {
			// No quota configured — allow request (fail-open)
			c.Next()
			return
		}

		// Check circuit breaker
		if circuitBreakerOpen {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "Circuit breaker is open. LLM calls are suspended for this tenant.",
				"code":    "CIRCUIT_BREAKER_OPEN",
			})
			return
		}

		// Check hard token limit
		if monthlyTokenLimit > 0 && monthlyTokensUsed >= monthlyTokenLimit {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "Monthly token quota exceeded.",
				"code":    "TOKEN_QUOTA_EXCEEDED",
				"usage":   monthlyTokensUsed,
				"limit":   monthlyTokenLimit,
			})
			return
		}

		// Check hard cost limit
		if monthlyCostLimitUSD > 0 && monthlyCostUsedUSD >= monthlyCostLimitUSD {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "Monthly cost quota exceeded.",
				"code":    "COST_QUOTA_EXCEEDED",
				"usage":   monthlyCostUsedUSD,
				"limit":   monthlyCostLimitUSD,
			})
			return
		}

		// Check warning threshold and add header
		tokenUsagePct := float64(0)
		if monthlyTokenLimit > 0 {
			tokenUsagePct = float64(monthlyTokensUsed) / float64(monthlyTokenLimit) * 100
		}
		costUsagePct := float64(0)
		if monthlyCostLimitUSD > 0 {
			costUsagePct = monthlyCostUsedUSD / monthlyCostLimitUSD * 100
		}

		if tokenUsagePct >= float64(warnThresholdPct) || costUsagePct >= float64(warnThresholdPct) {
			maxPct := tokenUsagePct
			if costUsagePct > maxPct {
				maxPct = costUsagePct
			}
			c.Header("X-Hydra-Quota-Warning", fmt.Sprintf("%.1f%% of quota used", maxPct))
		}

		c.Next()
	}
}
