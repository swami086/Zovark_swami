package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/analytics/feedback/summary — per-source FP rates, per-rule accuracy, 30-day trend
func feedbackSummaryHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Per-source FP rates
	sourceRows, err := dbPool.Query(c.Request.Context(), `
		SELECT
			COALESCE(t.task_type, 'unknown') AS source,
			COUNT(*) AS total,
			SUM(CASE WHEN f.false_positive THEN 1 ELSE 0 END) AS fp_count,
			ROUND(AVG(CASE WHEN f.false_positive THEN 1.0 ELSE 0.0 END)::numeric, 3) AS fp_rate
		FROM investigation_feedback f
		JOIN agent_tasks t ON t.id::text = f.investigation_id::text
		WHERE f.tenant_id = $1 AND f.created_at >= NOW() - INTERVAL '90 days'
		GROUP BY t.task_type
		ORDER BY fp_rate DESC
	`, tenantID)

	var sources []map[string]interface{}
	if err == nil {
		defer sourceRows.Close()
		for sourceRows.Next() {
			var source string
			var total, fpCount int
			var fpRate float64
			if err := sourceRows.Scan(&source, &total, &fpCount, &fpRate); err == nil {
				sources = append(sources, map[string]interface{}{
					"source":   source,
					"total":    total,
					"fp_count": fpCount,
					"fp_rate":  fpRate,
				})
			}
		}
	}
	if sources == nil {
		sources = []map[string]interface{}{}
	}

	// Overall accuracy
	var totalFeedback, correct, incorrect, fps, missed int
	var accuracyRate, avgConfidence float64
	_ = dbPool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN verdict_correct THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN NOT verdict_correct THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN false_positive THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN missed_threat THEN 1 ELSE 0 END), 0),
			COALESCE(ROUND(AVG(CASE WHEN verdict_correct THEN 1.0 ELSE 0.0 END)::numeric, 3), 0),
			COALESCE(ROUND(AVG(analyst_confidence)::numeric, 3), 0)
		FROM investigation_feedback
		WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '30 days'
	`, tenantID).Scan(&totalFeedback, &correct, &incorrect, &fps, &missed, &accuracyRate, &avgConfidence)

	c.JSON(http.StatusOK, gin.H{
		"total_feedback":       totalFeedback,
		"correct":              correct,
		"incorrect":            incorrect,
		"false_positives":      fps,
		"missed_threats":       missed,
		"accuracy_rate":        accuracyRate,
		"avg_confidence":       avgConfidence,
		"sources":              sources,
		"period_days":          30,
	})
}

// GET /api/v1/analytics/feedback/rules — rules ranked by accuracy
func feedbackRulesHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT
			COALESCE(t.input->>'rule_name', t.input->>'alert_name', 'unknown') AS rule_name,
			COUNT(*) AS total,
			SUM(CASE WHEN f.verdict_correct THEN 1 ELSE 0 END) AS correct,
			ROUND(AVG(CASE WHEN f.verdict_correct THEN 1.0 ELSE 0.0 END)::numeric, 3) AS accuracy
		FROM investigation_feedback f
		JOIN agent_tasks t ON t.id::text = f.investigation_id::text
		WHERE f.tenant_id = $1
		GROUP BY rule_name
		HAVING COUNT(*) >= 3
		ORDER BY accuracy ASC
	`, tenantID)

	var rules []map[string]interface{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ruleName string
			var total, correct int
			var accuracy float64
			if err := rows.Scan(&ruleName, &total, &correct, &accuracy); err == nil {
				rules = append(rules, map[string]interface{}{
					"rule_name":    ruleName,
					"total":        total,
					"correct":      correct,
					"accuracy":     accuracy,
					"needs_review": total >= 10 && accuracy < 0.3,
				})
			}
		}
	}
	if rules == nil {
		rules = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules, "count": len(rules)})
}

// GET /api/v1/analytics/feedback/analysts — per-analyst feedback volume
func feedbackAnalystsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT
			COALESCE(u.username, f.analyst_id::text) AS analyst,
			COUNT(*) AS total_feedback,
			SUM(CASE WHEN f.verdict_correct THEN 1 ELSE 0 END) AS agreed,
			SUM(CASE WHEN NOT f.verdict_correct THEN 1 ELSE 0 END) AS disagreed,
			ROUND(AVG(f.analyst_confidence)::numeric, 3) AS avg_confidence
		FROM investigation_feedback f
		LEFT JOIN users u ON u.id = f.analyst_id
		WHERE f.tenant_id = $1 AND f.created_at >= NOW() - INTERVAL '30 days'
		GROUP BY analyst
		ORDER BY total_feedback DESC
	`, tenantID)

	var analysts []map[string]interface{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var analyst string
			var total, agreed, disagreed int
			var avgConf float64
			if err := rows.Scan(&analyst, &total, &agreed, &disagreed, &avgConf); err == nil {
				analysts = append(analysts, map[string]interface{}{
					"analyst":        analyst,
					"total_feedback": total,
					"agreed":         agreed,
					"disagreed":      disagreed,
					"avg_confidence": avgConf,
				})
			}
		}
	}
	if analysts == nil {
		analysts = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"analysts": analysts, "count": len(analysts)})
}
