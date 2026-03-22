package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/detections/rules
// Returns detection rules. Filterable by technique_id, status.
func listDetectionRulesHandler(c *gin.Context) {
	techniqueID := c.Query("technique_id")
	status := c.Query("status")

	query := `
		SELECT id, technique_id, rule_name, rule_version, sigma_yaml,
		       status, tp_rate, fp_rate, investigations_matched,
		       tenant_spread, confidence, tp_count, fp_count,
		       source_technique, validated_at, last_matched, created_at
		FROM detection_rules
		WHERE 1=1
	`
	args := []interface{}{}
	argIdx := 1

	if techniqueID != "" {
		query += " AND technique_id = " + fmtArg(argIdx)
		args = append(args, techniqueID)
		argIdx++
	}

	if status != "" {
		query += " AND status = " + fmtArg(argIdx)
		args = append(args, status)
		argIdx++
	}

	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := dbPool.Query(c.Request.Context(), query, args...)
	if err != nil {
		respondInternalError(c, err, "list detection rules")
		return
	}
	defer rows.Close()

	var rules []map[string]interface{}
	for rows.Next() {
		var id, techniqueIDVal, ruleName, statusVal, sigmaYaml string
		var ruleVersion, investigationsMatched int
		var tpRate, fpRate *float64
		var tenantSpread *int
		var confidence *float64
		var tpCount, fpCount *int
		var sourceTechnique *string
		var validatedAt, lastMatched, createdAt interface{}

		err := rows.Scan(&id, &techniqueIDVal, &ruleName, &ruleVersion, &sigmaYaml,
			&statusVal, &tpRate, &fpRate, &investigationsMatched,
			&tenantSpread, &confidence, &tpCount, &fpCount,
			&sourceTechnique, &validatedAt, &lastMatched, &createdAt)
		if err != nil {
			respondInternalError(c, err, "scan detection rule row")
			return
		}

		rule := map[string]interface{}{
			"id":                     id,
			"technique_id":           techniqueIDVal,
			"rule_name":              ruleName,
			"rule_version":           ruleVersion,
			"sigma_yaml":             sigmaYaml,
			"status":                 statusVal,
			"tp_rate":                tpRate,
			"fp_rate":                fpRate,
			"investigations_matched": investigationsMatched,
			"tenant_spread":          tenantSpread,
			"confidence":             confidence,
			"tp_count":               tpCount,
			"fp_count":               fpCount,
			"source_technique":       sourceTechnique,
			"validated_at":           validatedAt,
			"last_matched":           lastMatched,
			"created_at":             createdAt,
		}
		rules = append(rules, rule)
	}

	if rules == nil {
		rules = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

// GET /api/v1/detections/stats
// Returns detection engine statistics.
func detectionStatsHandler(c *gin.Context) {
	// Total rules by status
	var totalRules, activeRules, testingRules, retiredRules, candidateRules int
	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*),
			COALESCE(COUNT(*) FILTER (WHERE status = 'active'), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'testing'), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'retired'), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'candidate'), 0)
		FROM detection_rules
	`).Scan(&totalRules, &activeRules, &testingRules, &retiredRules, &candidateRules)
	if err != nil {
		respondInternalError(c, err, "count detection rules")
		return
	}

	// Total candidates by status
	var totalCandidates, candidatePending, candidateApproved, candidateRejected int
	err = dbPool.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*),
			COALESCE(COUNT(*) FILTER (WHERE status = 'candidate'), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'approved'), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'rejected'), 0)
		FROM detection_candidates
	`).Scan(&totalCandidates, &candidatePending, &candidateApproved, &candidateRejected)
	if err != nil {
		respondInternalError(c, err, "count detection candidates")
		return
	}

	// Rules by technique
	techRows, err := dbPool.Query(c.Request.Context(), `
		SELECT technique_id, COUNT(*) as cnt
		FROM detection_rules
		WHERE status IN ('active', 'testing', 'candidate')
		GROUP BY technique_id
		ORDER BY cnt DESC
		LIMIT 20
	`)
	if err != nil {
		respondInternalError(c, err, "query rules by technique")
		return
	}
	defer techRows.Close()

	rulesByTechnique := map[string]int{}
	for techRows.Next() {
		var tech string
		var cnt int
		techRows.Scan(&tech, &cnt)
		rulesByTechnique[tech] = cnt
	}

	// Recent rules
	recentRows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, technique_id, rule_name, status, created_at
		FROM detection_rules
		ORDER BY created_at DESC
		LIMIT 5
	`)
	if err != nil {
		respondInternalError(c, err, "query recent rules")
		return
	}
	defer recentRows.Close()

	var recentRules []map[string]interface{}
	for recentRows.Next() {
		var id, tech, name, status string
		var createdAt interface{}
		recentRows.Scan(&id, &tech, &name, &status, &createdAt)
		recentRules = append(recentRules, map[string]interface{}{
			"id":           id,
			"technique_id": tech,
			"rule_name":    name,
			"status":       status,
			"created_at":   createdAt,
		})
	}
	if recentRules == nil {
		recentRules = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_rules":        totalRules,
		"active_rules":       activeRules,
		"testing_rules":      testingRules,
		"retired_rules":      retiredRules,
		"candidate_rules":    candidateRules,
		"total_candidates":   totalCandidates,
		"candidates_pending": candidatePending,
		"candidates_approved": candidateApproved,
		"candidates_rejected": candidateRejected,
		"rules_by_technique": rulesByTechnique,
		"recent_rules":       recentRules,
	})
}

// fmtArg returns "$N" for parameterized query building.
func fmtArg(i int) string {
	return fmt.Sprintf("$%d", i)
}
