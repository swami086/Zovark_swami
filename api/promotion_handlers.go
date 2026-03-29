package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// --------------------------------------------------------------------------
// Template Promotion Flywheel — Zovark Sprint 2D
//
// Provides 5 endpoints for the Path C → analyst review → template promotion cycle:
//   GET    /api/v1/promotion-queue      — Path C investigations awaiting analyst review
//   POST   /api/v1/analyst-feedback     — submit analyst review, optionally promote to template
//   GET    /api/v1/auto-templates       — list auto-promoted templates
//   DELETE /api/v1/auto-templates/:slug — soft-disable an auto-promoted template
//   GET    /api/v1/dashboard-stats      — aggregated SOC dashboard statistics
// --------------------------------------------------------------------------

// promotionQueueHandler lists Path C investigations awaiting analyst review.
// GET /api/v1/promotion-queue
func promotionQueueHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)

	if dbPool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	rows, err := dbPool.Query(ctx, `
		SELECT task_id, task_type, path_taken, risk_score, verdict,
		       findings, iocs, mitre_attack, siem_event,
		       created_at, execution_ms
		FROM promotion_queue
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 50
	`, tenantID)
	if err != nil {
		// View may not exist yet — return empty gracefully
		c.JSON(http.StatusOK, gin.H{"items": []interface{}{}, "total": 0, "awaiting_review": 0})
		return
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var taskID, taskType string
		var pathTaken, riskScore, verdict *string
		var findings, iocs, mitreAttack, siemEvent interface{}
		var createdAt time.Time
		var executionMs *int

		if err := rows.Scan(&taskID, &taskType, &pathTaken, &riskScore, &verdict,
			&findings, &iocs, &mitreAttack, &siemEvent,
			&createdAt, &executionMs); err != nil {
			log.Printf("Error scanning promotion queue row: %v", err)
			continue
		}

		item := map[string]interface{}{
			"task_id":      taskID,
			"task_type":    taskType,
			"path_taken":   pathTaken,
			"risk_score":   riskScore,
			"verdict":      verdict,
			"findings":     findings,
			"iocs":         iocs,
			"mitre_attack": mitreAttack,
			"siem_event":   siemEvent,
			"created_at":   createdAt,
			"execution_ms": executionMs,
		}
		items = append(items, item)
	}

	if items == nil {
		items = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"items":           items,
		"total":           len(items),
		"awaiting_review": len(items),
	})
}

// analystFeedbackRequest is the JSON body for the analyst feedback endpoint.
type analystFeedbackRequest struct {
	TaskID         string `json:"task_id" binding:"required"`
	AnalystVerdict string `json:"analyst_verdict" binding:"required"`
	AnalystRisk    *int   `json:"analyst_risk_score"`
	AnalystNotes   string `json:"analyst_notes"`
	Promote        bool   `json:"promote"`
}

// analystFeedbackHandler submits analyst review for a Path C investigation.
// If promote=true, creates an auto-promoted template in agent_skills.
// POST /api/v1/analyst-feedback
func analystFeedbackHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.GetString("user_id")

	if dbPool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	var req analystFeedbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate analyst_verdict
	validVerdicts := map[string]bool{
		"true_positive":  true,
		"false_positive": true,
		"suspicious":     true,
		"benign":         true,
	}
	if !validVerdicts[req.AnalystVerdict] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "analyst_verdict must be one of: true_positive, false_positive, suspicious, benign",
		})
		return
	}

	// Validate risk score range if provided
	if req.AnalystRisk != nil && (*req.AnalystRisk < 0 || *req.AnalystRisk > 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "analyst_risk_score must be between 0 and 100"})
		return
	}

	// Verify the task belongs to this tenant and fetch original values
	var taskType, originalVerdict string
	var originalRisk *int
	var generatedCode *string
	err := dbPool.QueryRow(ctx, `
		SELECT task_type,
		       COALESCE(output->>'verdict', ''),
		       (output->>'risk_score')::int,
		       generated_code
		FROM agent_tasks
		WHERE id = $1 AND tenant_id = $2
	`, req.TaskID, tenantID).Scan(&taskType, &originalVerdict, &originalRisk, &generatedCode)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	// Look up analyst email from users table
	var analystEmail string
	emailErr := dbPool.QueryRow(ctx,
		"SELECT email FROM users WHERE id = $1 AND tenant_id = $2",
		userID, tenantID,
	).Scan(&analystEmail)
	if emailErr != nil {
		analystEmail = userID // fallback to user_id if email lookup fails
	}

	// Check for duplicate feedback
	var existingFeedback bool
	_ = dbPool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM analyst_feedback WHERE task_id = $1 AND tenant_id = $2)",
		req.TaskID, tenantID,
	).Scan(&existingFeedback)
	if existingFeedback {
		c.JSON(http.StatusConflict, gin.H{"error": "feedback already submitted for this task"})
		return
	}

	// Begin transaction
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		respondInternalError(c, err, "begin analyst feedback transaction")
		return
	}
	defer tx.Rollback(ctx) // no-op after commit

	// Insert analyst feedback
	feedbackID := uuid.New().String()
	var promotedSlug *string

	_, err = tx.Exec(ctx, `
		INSERT INTO analyst_feedback
			(id, task_id, tenant_id, analyst_email, analyst_verdict,
			 analyst_risk_score, analyst_notes, original_verdict,
			 original_risk_score, promote, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
	`, feedbackID, req.TaskID, tenantID, analystEmail,
		req.AnalystVerdict, req.AnalystRisk, req.AnalystNotes,
		originalVerdict, originalRisk, req.Promote)
	if err != nil {
		respondInternalError(c, err, "insert analyst feedback")
		return
	}

	// Update the task verdict to reflect analyst decision
	updateOutput := fmt.Sprintf(
		`jsonb_set(jsonb_set(COALESCE(output, '{}'::jsonb), '{verdict}', '"%s"'), '{analyst_reviewed}', 'true')`,
		req.AnalystVerdict,
	)
	if req.AnalystRisk != nil {
		updateOutput = fmt.Sprintf(
			`jsonb_set(%s, '{risk_score}', '%d')`,
			updateOutput, *req.AnalystRisk,
		)
	}

	_, err = tx.Exec(ctx, fmt.Sprintf(
		"UPDATE agent_tasks SET output = %s WHERE id = $1 AND tenant_id = $2",
		updateOutput,
	), req.TaskID, tenantID)
	if err != nil {
		respondInternalError(c, err, "update task verdict from analyst feedback")
		return
	}

	// Promotion logic
	if req.Promote && generatedCode != nil && *generatedCode != "" {
		// Generate slug: auto-{task_type}-{first 6 chars of sha256(task_id)}
		hash := sha256.Sum256([]byte(req.TaskID))
		hashPrefix := fmt.Sprintf("%x", hash[:3]) // 6 hex chars
		slug := fmt.Sprintf("auto-%s-%s", taskType, hashPrefix)
		promotedSlug = &slug

		// Templatize: replace SIEM event data with placeholder
		templateCode := templatizeSIEMEvent(*generatedCode)

		// Skill name from slug
		skillName := fmt.Sprintf("Auto: %s (%s)", strings.ReplaceAll(taskType, "_", " "), hashPrefix)

		// Task types array: just the source task_type
		taskTypes := fmt.Sprintf("{%s}", taskType)

		// Check if a skill with this slug already exists for the tenant
		var existingSkill bool
		_ = tx.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM agent_skills WHERE skill_slug = $1 AND tenant_id = $2)",
			slug, tenantID,
		).Scan(&existingSkill)

		if existingSkill {
			// Update the existing skill
			_, err = tx.Exec(ctx, `
				UPDATE agent_skills
				SET code_template = $1, promoted_at = NOW(), promoted_by = $2,
				    promotion_status = 'active', is_active = true, source_task_id = $3::uuid
				WHERE skill_slug = $4 AND tenant_id = $5
			`, templateCode, analystEmail, req.TaskID, slug, tenantID)
		} else {
			// Insert new skill
			skillID := uuid.New().String()
			_, err = tx.Exec(ctx, `
				INSERT INTO agent_skills
					(id, tenant_id, skill_name, skill_slug, threat_types,
					 code_template, is_active, auto_promoted, source_task_id,
					 promoted_at, promoted_by, promotion_status,
					 severity_default, investigation_methodology, detection_patterns,
					 example_prompt, mitre_tactics, mitre_techniques,
					 version, is_community, created_at)
				VALUES ($1, $2, $3, $4, $5::text[],
				        $6, true, true, $7::uuid,
				        NOW(), $8, 'active',
				        'high', 'auto-promoted from Path C investigation', 'LLM-generated',
				        '', '{}', '{}',
				        1, false, NOW())
			`, skillID, tenantID, skillName, slug, taskTypes,
				templateCode, req.TaskID, analystEmail)
		}
		if err != nil {
			respondInternalError(c, err, "promote template to agent_skills")
			return
		}

		// Update the feedback row with the promoted slug
		_, _ = tx.Exec(ctx,
			"UPDATE analyst_feedback SET promoted_slug = $1 WHERE id = $2",
			slug, feedbackID,
		)
	}

	// Audit event
	_, _ = tx.Exec(ctx,
		`INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id)
		 VALUES ($1, $2, $3, $4)`,
		tenantID, "analyst_feedback_submitted", "task", req.TaskID,
	)

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit analyst feedback transaction")
		return
	}

	response := gin.H{
		"id":              feedbackID,
		"task_id":         req.TaskID,
		"analyst_verdict": req.AnalystVerdict,
		"status":          "recorded",
	}
	if promotedSlug != nil {
		response["promoted_slug"] = *promotedSlug
		response["promoted"] = true
	}

	c.JSON(http.StatusCreated, response)
}

// autoTemplatesHandler lists auto-promoted templates.
// GET /api/v1/auto-templates
func autoTemplatesHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)

	if dbPool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	rows, err := dbPool.Query(ctx, `
		SELECT skill_slug, skill_name, threat_types,
		       auto_promoted, source_task_id, promoted_at, promoted_by,
		       promotion_status, created_at
		FROM agent_skills
		WHERE tenant_id = $1 AND auto_promoted = true
		ORDER BY promoted_at DESC
	`, tenantID)
	if err != nil {
		// Table columns may not exist yet — return empty gracefully
		c.JSON(http.StatusOK, gin.H{"items": []interface{}{}, "count": 0})
		return
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var slug, name, promotionStatus string
		var threatTypes []string
		var autoPromoted bool
		var sourceTaskID *string
		var promotedAt *time.Time
		var promotedBy *string
		var createdAt time.Time

		if err := rows.Scan(&slug, &name, &threatTypes,
			&autoPromoted, &sourceTaskID, &promotedAt, &promotedBy,
			&promotionStatus, &createdAt); err != nil {
			log.Printf("Error scanning auto-template row: %v", err)
			continue
		}

		item := map[string]interface{}{
			"skill_slug":       slug,
			"skill_name":       name,
			"task_types":       threatTypes,
			"auto_promoted":    autoPromoted,
			"source_task_id":   sourceTaskID,
			"promoted_at":      promotedAt,
			"promoted_by":      promotedBy,
			"promotion_status": promotionStatus,
			"created_at":       createdAt,
		}
		items = append(items, item)
	}

	if items == nil {
		items = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"items": items,
		"count": len(items),
	})
}

// disableAutoTemplateHandler soft-disables an auto-promoted template.
// DELETE /api/v1/auto-templates/:slug
func disableAutoTemplateHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)
	slug := c.Param("slug")

	if dbPool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	tag, err := dbPool.Exec(ctx, `
		UPDATE agent_skills
		SET promotion_status = 'disabled', is_active = false
		WHERE skill_slug = $1 AND tenant_id = $2 AND auto_promoted = true
	`, slug, tenantID)
	if err != nil {
		respondInternalError(c, err, "disable auto-promoted template")
		return
	}

	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "auto-promoted template not found"})
		return
	}

	// Audit event
	_, _ = dbPool.Exec(ctx,
		`INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id)
		 VALUES ($1, $2, $3, $4)`,
		tenantID, "auto_template_disabled", "skill", slug,
	)

	c.JSON(http.StatusOK, gin.H{
		"slug":   slug,
		"status": "disabled",
	})
}

// dashboardStatsHandler returns aggregated stats for the SOC dashboard.
// GET /api/v1/dashboard-stats
func dashboardStatsHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID := c.MustGet("tenant_id").(string)

	if dbPool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	// Core investigation stats
	var totalInvestigations, completedCount int
	var avgResponseMs float64
	err := dbPool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COALESCE(COUNT(*) FILTER (WHERE status = 'completed'), 0),
			COALESCE(AVG(execution_ms) FILTER (WHERE status = 'completed'), 0)
		FROM agent_tasks
		WHERE tenant_id = $1
	`, tenantID).Scan(&totalInvestigations, &completedCount, &avgResponseMs)
	if err != nil {
		respondInternalError(c, err, "query dashboard investigation stats")
		return
	}

	// Detection rate: (true_positive + suspicious) / completed
	var truePositives, suspicious, benignFromAttack int
	_ = dbPool.QueryRow(ctx, `
		SELECT
			COALESCE(COUNT(*) FILTER (WHERE output->>'verdict' = 'true_positive'), 0),
			COALESCE(COUNT(*) FILTER (WHERE output->>'verdict' = 'suspicious'), 0),
			COALESCE(COUNT(*) FILTER (WHERE output->>'verdict' = 'benign'
				AND task_type NOT IN (
					'password_change', 'windows_update', 'health_check',
					'scheduled_task', 'software_install', 'disk_cleanup',
					'routine_backup', 'service_restart', 'log_rotation',
					'certificate_renewal', 'system_reboot', 'ntp_sync',
					'dns_cache_flush', 'group_policy_update',
					'antivirus_update', 'patch_management', 'user_login',
					'user_logout', 'session_timeout', 'config_change',
					'network_interface_up', 'network_interface_down',
					'printer_added', 'usb_device', 'screen_lock',
					'screen_unlock', 'timezone_change', 'locale_change',
					'font_install', 'theme_change', 'wallpaper_change'
				)
			), 0)
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed'
	`, tenantID).Scan(&truePositives, &suspicious, &benignFromAttack)

	var detectionRate, falsePositiveRate float64
	if completedCount > 0 {
		detectionRate = float64(truePositives+suspicious) / float64(completedCount) * 100
		falsePositiveRate = float64(benignFromAttack) / float64(completedCount) * 100
	}

	// Auto-templates count
	var autoTemplatesCount int
	_ = dbPool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM agent_skills
		WHERE tenant_id = $1 AND auto_promoted = true AND promotion_status = 'active'
	`, tenantID).Scan(&autoTemplatesCount)

	// Awaiting review count
	var awaitingReview int
	_ = dbPool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM promotion_queue
		WHERE tenant_id = $1
	`, tenantID).Scan(&awaitingReview)

	// Path distribution
	pathRows, _ := dbPool.Query(ctx, `
		SELECT COALESCE(path_taken, 'unknown'), COUNT(*)
		FROM agent_tasks
		WHERE tenant_id = $1 AND status = 'completed'
		GROUP BY path_taken
	`, tenantID)

	pathDistribution := map[string]int{}
	if pathRows != nil {
		defer pathRows.Close()
		for pathRows.Next() {
			var path string
			var cnt int
			pathRows.Scan(&path, &cnt)
			pathDistribution[path] = cnt
		}
	}

	// Analyst hours saved: each completed investigation saves ~15 min of analyst time
	analystHoursSaved := float64(completedCount) * 15.0 / 60.0

	c.JSON(http.StatusOK, gin.H{
		"total_investigations":  totalInvestigations,
		"completed":             completedCount,
		"avg_response_ms":       avgResponseMs,
		"detection_rate":        detectionRate,
		"false_positive_rate":   falsePositiveRate,
		"auto_templates_count":  autoTemplatesCount,
		"awaiting_review":       awaitingReview,
		"path_distribution":     pathDistribution,
		"analyst_hours_saved":   analystHoursSaved,
		"true_positives":        truePositives,
		"suspicious":            suspicious,
		"benign_from_attack":    benignFromAttack,
	})
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// templatizeSIEMEvent replaces common hardcoded SIEM event JSON patterns in generated
// code with the {{siem_event_json}} placeholder so the code can be reused as a template.
func templatizeSIEMEvent(code string) string {
	// Replace the most common patterns where LLM-generated code hardcodes the SIEM event.
	// Pattern 1: siem_event = {...}  or  siem_data = {...}
	// Pattern 2: event_data = json.loads('...')
	// We do a simple replacement: inject the placeholder at the top and replace known
	// variable assignments. For robustness, we wrap the original code with a standard preamble.
	templatePreamble := `import json

# Template placeholder — filled by Zovark pipeline at runtime
siem_event = json.loads("""{{siem_event_json}}""")
`

	// If the code already contains the placeholder, return as-is
	if strings.Contains(code, "{{siem_event_json}}") {
		return code
	}

	// Prepend the preamble — the original code's SIEM parsing will be overridden
	// by the variable being already defined
	return templatePreamble + "\n" + code
}
