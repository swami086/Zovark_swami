package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.temporal.io/sdk/client"
)

// Types
type TaskRequest struct {
	TaskType string                 `json:"task_type"`
	Input    map[string]interface{} `json:"input" binding:"required"`
}

func healthCheckHandler(c *gin.Context) {
	deploymentMode := getEnvOrDefault("HYDRA_DEPLOYMENT_MODE", "cloud")
	llmModel := getEnvOrDefault("HYDRA_LLM_MODEL", "fast")

	llmProvider := "OpenRouter (Cloud)"
	if llmModel == "hydra-local" {
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
		"version":            "1.1.0",
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

func createTaskHandler(c *gin.Context) {
	var req TaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. Get tenant_id from authenticated context
	tenantID := c.MustGet("tenant_id").(string)

	// Playbook resolution
	if pid, ok := req.Input["playbook_id"].(string); ok && pid != "" {
		var playbookTaskType string
		var playbookStepsJSON []byte
		var playbookSystemPrompt *string
		err := dbPool.QueryRow(c.Request.Context(),
			"SELECT task_type, steps, system_prompt_override FROM playbooks WHERE id = $1 AND (tenant_id = $2 OR is_template = true)",
			pid, tenantID,
		).Scan(&playbookTaskType, &playbookStepsJSON, &playbookSystemPrompt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or inaccessible playbook_id"})
			return
		}

		var playbookSteps []string
		if err := json.Unmarshal(playbookStepsJSON, &playbookSteps); err == nil {
			req.Input["playbook_steps"] = playbookSteps
			if prompt, hasPrompt := req.Input["prompt"].(string); (!hasPrompt || prompt == "") && len(playbookSteps) > 0 {
				req.Input["prompt"] = playbookSteps[0]
			}
		}

		req.TaskType = playbookTaskType
		if playbookSystemPrompt != nil {
			req.Input["playbook_system_prompt_override"] = *playbookSystemPrompt
		}
	}

	if req.TaskType == "" {
		req.TaskType = "log_analysis"
	}

	// --- ALERT DEDUPLICATION (Sprint 5) ---
	// Compute SHA-256 fingerprint of normalized alert fields
	fpFields := []string{tenantID, req.TaskType}
	if prompt, ok := req.Input["prompt"].(string); ok {
		fpFields = append(fpFields, strings.ToLower(strings.TrimSpace(prompt)))
	}
	if srcIP, ok := req.Input["source_ip"].(string); ok {
		fpFields = append(fpFields, strings.TrimSpace(srcIP))
	}
	if dstIP, ok := req.Input["dest_ip"].(string); ok {
		fpFields = append(fpFields, strings.TrimSpace(dstIP))
	}
	sort.Strings(fpFields[2:]) // Sort fields after tenant_id and task_type
	fpHash := sha256.Sum256([]byte(strings.Join(fpFields, "|")))
	fingerprint := hex.EncodeToString(fpHash[:])

	// Check for existing fingerprint within dedup window
	var existingInvID *string
	var existingCount int
	dedupErr := dbPool.QueryRow(c.Request.Context(),
		`SELECT investigation_id, alert_count FROM alert_fingerprints
		 WHERE tenant_id = $1 AND fingerprint = $2
		 AND last_seen > NOW() - (dedup_window_seconds * interval '1 second')`,
		tenantID, fingerprint,
	).Scan(&existingInvID, &existingCount)

	if dedupErr == nil && existingInvID != nil {
		// Duplicate alert — increment count and return existing
		_, _ = dbPool.Exec(c.Request.Context(),
			`UPDATE alert_fingerprints SET last_seen = NOW(), alert_count = alert_count + 1
			 WHERE tenant_id = $1 AND fingerprint = $2`,
			tenantID, fingerprint,
		)
		c.JSON(http.StatusOK, gin.H{
			"status":           "deduplicated",
			"investigation_id": *existingInvID,
			"alert_count":      existingCount + 1,
			"fingerprint":      fingerprint,
		})
		return
	}

	// 2. Generate task ID
	taskID := uuid.New().String()

	// Insert new fingerprint record (investigation_id will be updated later)
	rawSample, _ := json.Marshal(req.Input)
	_, _ = dbPool.Exec(c.Request.Context(),
		`INSERT INTO alert_fingerprints (tenant_id, fingerprint, alert_type, raw_sample)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING`,
		tenantID, fingerprint, req.TaskType, rawSample,
	)

	// 3. Insert into agent_tasks (with 5s lock timeout)
	priority := extractPriority(req.Input)
	dbCtx, dbCancel := dbContextWithTimeout(c.Request.Context())
	defer dbCancel()

	_, err := dbPool.Exec(dbCtx,
		"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		taskID, tenantID, req.TaskType, req.Input, "pending", time.Now(),
	)
	if err != nil {
		if isLockTimeout(err) {
			HandlePostgresLock(c, tenantID, taskID, priority, "INSERT", "agent_tasks", 5000)
			return
		}
		respondInternalError(c, err, "create task record")
		return
	}

	// 4. Log to agent_audit_log
	_, errAudit := dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id) VALUES ($1, $2, $3, $4)",
		tenantID, "task_created", "task", taskID,
	)
	if errAudit != nil {
		log.Printf("Failed to insert audit log for task_created: %v", errAudit)
	}

	// 5. Start Temporal Workflow (with timeout detection for model failover)
	workflowOptions := client.StartWorkflowOptions{
		ID:        "task-" + taskID,
		TaskQueue: "hydra-tasks",
	}

	wfStart := time.Now()
	we, err := tc.ExecuteWorkflow(context.Background(), workflowOptions, "ExecuteTaskWorkflow", req)
	wfLatency := int(time.Since(wfStart).Milliseconds())

	if err != nil {
		if isTemporalTimeout(err) {
			fallbackModel := HandleModelTimeout(c.Request.Context(), tenantID, taskID, priority,
				wfLatency, "temporal/litellm", "hydra-fast")
			log.Printf("Model timeout on task %s, fallback to %s", taskID, fallbackModel)
		}
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
		respondInternalError(c, err, "start workflow")
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"task_id":     taskID,
		"workflow_id": we.GetID(),
		"status":      "pending",
	})
}

func getTaskHandler(c *gin.Context) {
	taskID := c.Param("id")

	var status, taskType string
	var input, output map[string]interface{}
	var createdAt, completedAt *time.Time
	var tokensInput, tokensOutput *int
	var executionMs *int
	var severity *string

	tenantID := c.MustGet("tenant_id").(string)

	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT status, task_type, input, output, created_at, completed_at, tokens_used_input, tokens_used_output, execution_ms, severity FROM agent_tasks WHERE id = $1 AND tenant_id = $2", taskID, tenantID,
	).Scan(&status, &taskType, &input, &output, &createdAt, &completedAt, &tokensInput, &tokensOutput, &executionMs, &severity)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	// Get step count and current step
	var stepCount int
	var currentStep *int
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT COUNT(*), MAX(step_number) FROM agent_task_steps WHERE task_id = $1", taskID,
	).Scan(&stepCount, &currentStep)

	// Get pending approval info
	var approvalStatus *string
	var pendingApprovalID *string
	var approvalRiskLevel *string
	var approvalReason *string
	_ = dbPool.QueryRow(c.Request.Context(),
		"SELECT id, status, risk_level, action_summary FROM approval_requests WHERE task_id = $1 ORDER BY requested_at DESC LIMIT 1", taskID,
	).Scan(&pendingApprovalID, &approvalStatus, &approvalRiskLevel, &approvalReason)

	c.JSON(http.StatusOK, gin.H{
		"task_id":             taskID,
		"status":              status,
		"task_type":           taskType,
		"input":               input,
		"output":              output,
		"created_at":          createdAt,
		"completed_at":        completedAt,
		"tokens_used_input":   tokensInput,
		"tokens_used_output":  tokensOutput,
		"execution_ms":        executionMs,
		"severity":            severity,
		"step_count":          stepCount,
		"current_step":        currentStep,
		"approval_status":     approvalStatus,
		"pending_approval_id": pendingApprovalID,
		"approval_risk_level": approvalRiskLevel,
		"approval_reason":     approvalReason,
	})
}

func listTasksHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Parse query params
	search := c.Query("search")
	status := c.Query("status")
	severity := c.Query("severity")
	taskType := c.Query("task_type")
	dateFrom := c.Query("date_from")
	dateTo := c.Query("date_to")
	sortField := c.DefaultQuery("sort", "created_at")
	sortOrder := c.DefaultQuery("order", "desc")
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "20")

	page := 1
	limit := 20
	if v, err := fmt.Sscanf(pageStr, "%d", &page); v == 0 || err != nil || page < 1 {
		page = 1
	}
	if v, err := fmt.Sscanf(limitStr, "%d", &limit); v == 0 || err != nil || limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Whitelist sort fields
	allowedSorts := map[string]string{
		"created_at": "created_at",
		"status":     "status",
		"severity":   "task_type", // proxy sort
	}
	sortCol, ok := allowedSorts[sortField]
	if !ok {
		sortCol = "created_at"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	// Build WHERE clauses
	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	argN := 2

	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, status)
		argN++
	}
	if taskType != "" {
		where += fmt.Sprintf(" AND task_type = $%d", argN)
		args = append(args, taskType)
		argN++
	}
	if severity != "" {
		where += fmt.Sprintf(" AND input->>'severity' = $%d", argN)
		args = append(args, severity)
		argN++
	}
	if dateFrom != "" {
		where += fmt.Sprintf(" AND created_at >= $%d", argN)
		args = append(args, dateFrom)
		argN++
	}
	if dateTo != "" {
		where += fmt.Sprintf(" AND created_at <= ($%d::date + interval '1 day')", argN)
		args = append(args, dateTo)
		argN++
	}
	if search != "" {
		where += fmt.Sprintf(" AND (input->>'prompt' ILIKE $%d OR task_type ILIKE $%d)", argN, argN)
		args = append(args, "%"+search+"%")
		argN++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM agent_tasks " + where
	err := dbPool.QueryRow(c.Request.Context(), countQuery, args...).Scan(&total)
	if err != nil {
		respondInternalError(c, err, "count tasks")
		return
	}

	// Fetch page
	dataArgs := make([]interface{}, len(args))
	copy(dataArgs, args)
	dataArgs = append(dataArgs, limit, offset)

	query := fmt.Sprintf(
		"SELECT id, status, COALESCE(task_type, 'code_gen'), created_at, execution_ms, input->>'prompt' FROM agent_tasks %s ORDER BY %s %s LIMIT $%d OFFSET $%d",
		where, sortCol, sortOrder, argN, argN+1,
	)

	rows, err := dbPool.Query(c.Request.Context(), query, dataArgs...)
	if err != nil {
		respondInternalError(c, err, "query tasks")
		return
	}
	defer rows.Close()

	var tasks []map[string]interface{}
	for rows.Next() {
		var id, statusVal, taskTypeVal string
		var createdAt time.Time
		var executionMs *int
		var prompt *string

		if err := rows.Scan(&id, &statusVal, &taskTypeVal, &createdAt, &executionMs, &prompt); err != nil {
			log.Printf("Error scanning task row: %v", err)
			continue
		}

		task := map[string]interface{}{
			"id":           id,
			"status":       statusVal,
			"task_type":    taskTypeVal,
			"created_at":   createdAt,
			"execution_ms": executionMs,
			"prompt":       prompt,
		}
		tasks = append(tasks, task)
	}

	if tasks == nil {
		tasks = []map[string]interface{}{}
	}

	pages := (total + limit - 1) / limit

	c.JSON(http.StatusOK, gin.H{
		"tasks": tasks,
		"total": total,
		"page":  page,
		"limit": limit,
		"pages": pages,
	})
}

func getTaskAuditHandler(c *gin.Context) {
	taskID := c.Param("id")

	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT action, created_at, details FROM agent_audit_log WHERE resource_id = $1 AND tenant_id = $2 ORDER BY created_at ASC", taskID, tenantID)
	if err != nil {
		respondInternalError(c, err, "query task audit log")
		return
	}
	defer rows.Close()

	var audits []map[string]interface{}
	for rows.Next() {
		var action string
		var timestamp time.Time
		var details map[string]interface{}

		if err := rows.Scan(&action, &timestamp, &details); err != nil {
			respondInternalError(c, err, "parse task audit log row")
			return
		}

		audit := map[string]interface{}{
			"action":    action,
			"timestamp": timestamp,
			"details":   details,
		}
		audits = append(audits, audit)
	}

	if audits == nil {
		audits = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"audit_trail": audits})
}

func getStatsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var totalTasks, completed, failed, pending, executing, inTokens, outTokens int

	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT 
			COUNT(*) as total_tasks,
			COALESCE(COUNT(*) FILTER (WHERE status = 'completed'), 0) as completed,
			COALESCE(COUNT(*) FILTER (WHERE status = 'failed'), 0) as failed,
			COALESCE(COUNT(*) FILTER (WHERE status = 'pending'), 0) as pending,
			COALESCE(COUNT(*) FILTER (WHERE status = 'executing'), 0) as executing,
			COALESCE(SUM(tokens_used_input), 0) as total_tokens_input,
			COALESCE(SUM(tokens_used_output), 0) as total_tokens_output
		FROM agent_tasks WHERE tenant_id = $1
	`, tenantID).Scan(&totalTasks, &completed, &failed, &pending, &executing, &inTokens, &outTokens)

	if err != nil {
		respondInternalError(c, err, "calculate task stats")
		return
	}

	// Task type distribution
	typeRows, _ := dbPool.Query(c.Request.Context(),
		"SELECT COALESCE(task_type, 'unknown'), COUNT(*) FROM agent_tasks WHERE tenant_id = $1 GROUP BY task_type", tenantID)
	typeDistribution := map[string]int{}
	if typeRows != nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var tt string
			var cnt int
			typeRows.Scan(&tt, &cnt)
			typeDistribution[tt] = cnt
		}
	}

	// SIEM alert stats
	var siemTotal, siemNew, siemInvestigating int
	_ = dbPool.QueryRow(c.Request.Context(), `
		SELECT 
			COALESCE(COUNT(*), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'new'), 0),
			COALESCE(COUNT(*) FILTER (WHERE status = 'investigating'), 0)
		FROM siem_alerts WHERE tenant_id = $1
	`, tenantID).Scan(&siemTotal, &siemNew, &siemInvestigating)

	// Recent activity
	actRows, _ := dbPool.Query(c.Request.Context(),
		"SELECT id, status, COALESCE(task_type, 'unknown'), created_at, input->>'prompt' FROM agent_tasks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 10", tenantID)
	var recentActivity []map[string]interface{}
	if actRows != nil {
		defer actRows.Close()
		for actRows.Next() {
			var id, status, tt string
			var createdAt time.Time
			var prompt *string
			actRows.Scan(&id, &status, &tt, &createdAt, &prompt)
			recentActivity = append(recentActivity, map[string]interface{}{
				"id": id, "status": status, "task_type": tt, "created_at": createdAt, "prompt": prompt,
			})
		}
	}
	if recentActivity == nil {
		recentActivity = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_tasks":               totalTasks,
		"completed":                 completed,
		"failed":                    failed,
		"pending":                   pending,
		"executing":                 executing,
		"total_tokens_input":        inTokens,
		"total_tokens_output":       outTokens,
		"type_distribution":         typeDistribution,
		"siem_alerts_total":         siemTotal,
		"siem_alerts_new":           siemNew,
		"siem_alerts_investigating": siemInvestigating,
		"recent_activity":           recentActivity,
	})
}

func uploadTaskHandler(c *gin.Context) {
	const maxFileSize = 10 << 20 // 10MB
	const maxLogData = 50 * 1024 // 50KB for LLM context

	allowedExts := map[string]bool{".csv": true, ".json": true, ".txt": true, ".log": true}

	// Parse multipart form
	if err := c.Request.ParseMultipartForm(maxFileSize); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("File too large or bad form: %v", err)})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File field 'file' is required"})
		return
	}
	defer file.Close()

	// Validate extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExts[ext] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Allowed: .csv, .json, .txt, .log"})
		return
	}

	// Validate size
	if header.Size > int64(maxFileSize) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File exceeds 10MB limit"})
		return
	}

	// Read file content (cap at 50KB)
	readSize := header.Size
	if readSize > int64(maxLogData) {
		readSize = int64(maxLogData)
	}
	buf := make([]byte, readSize)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		respondInternalError(c, err, "read uploaded file")
		return
	}
	logData := string(buf[:n])

	// Get optional form fields
	taskType := c.PostForm("task_type")
	if taskType == "" {
		taskType = "Log Analysis"
	}
	prompt := c.PostForm("prompt")
	if prompt == "" {
		prompt = "Analyze this log file for security anomalies and threats"
	}

	// Get tenant_id from JWT
	tenantID := c.MustGet("tenant_id").(string)

	// Build input JSON
	inputMap := map[string]interface{}{
		"prompt":    prompt,
		"log_data":  logData,
		"filename":  header.Filename,
		"file_size": header.Size,
	}

	inputJSON, err := json.Marshal(inputMap)
	if err != nil {
		respondInternalError(c, err, "serialize upload task input")
		return
	}

	// Generate task ID
	taskID := uuid.New().String()

	// Insert into agent_tasks
	_, err = dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		taskID, tenantID, taskType, inputJSON, "pending", time.Now(),
	)
	if err != nil {
		respondInternalError(c, err, "create upload task record")
		return
	}

	// Audit log
	_, _ = dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id) VALUES ($1, $2, $3, $4)",
		tenantID, "task_created", "task", taskID,
	)

	// Start Temporal workflow
	workflowOptions := client.StartWorkflowOptions{
		ID:        "task-" + taskID,
		TaskQueue: "hydra-tasks",
	}

	req := TaskRequest{
		TaskType: taskType,
		Input:    inputMap,
	}

	we, err := tc.ExecuteWorkflow(context.Background(), workflowOptions, "ExecuteTaskWorkflow", req)
	if err != nil {
		_, _ = dbPool.Exec(c.Request.Context(), "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
		respondInternalError(c, err, "start upload workflow")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"task_id":     taskID,
		"workflow_id": we.GetID(),
		"status":      "pending",
		"filename":    header.Filename,
		"file_size":   header.Size,
	})
}

func getTaskStepsHandler(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	// Verify the task belongs to this tenant
	var exists bool
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM agent_tasks WHERE id = $1 AND tenant_id = $2)", taskID, tenantID,
	).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, step_number, step_type, prompt, generated_code, output, status, tokens_used_input, tokens_used_output, execution_ms, created_at, completed_at, execution_mode, parameters_used FROM investigation_steps WHERE task_id = $1 ORDER BY step_number ASC", taskID)
	if err != nil {
		respondInternalError(c, err, "query task steps")
		return
	}
	defer rows.Close()

	var steps []map[string]interface{}
	for rows.Next() {
		var stepID, stepType, prompt, status string
		var stepNumber, tokensIn, tokensOut int
		var generatedCode, output *string
		var executionMs *int
		var createdAt time.Time
		var completedAt *time.Time
		var executionMode *string
		var parametersUsed *string

		if err := rows.Scan(&stepID, &stepNumber, &stepType, &prompt, &generatedCode, &output, &status, &tokensIn, &tokensOut, &executionMs, &createdAt, &completedAt, &executionMode, &parametersUsed); err != nil {
			log.Printf("Error scanning step row: %v", err)
			continue
		}

		// Handle parameter deserialization safely
		var parsedParams map[string]interface{}
		if parametersUsed != nil {
			_ = json.Unmarshal([]byte(*parametersUsed), &parsedParams)
		}

		step := map[string]interface{}{
			"id":                 stepID,
			"step_number":        stepNumber,
			"step_type":          stepType,
			"prompt":             prompt,
			"generated_code":     generatedCode,
			"output":             output,
			"status":             status,
			"tokens_used_input":  tokensIn,
			"tokens_used_output": tokensOut,
			"execution_ms":       executionMs,
			"created_at":         createdAt,
			"completed_at":       completedAt,
			"execution_mode":     executionMode,
			"parameters_used":    parsedParams,
		}
		steps = append(steps, step)
	}

	if steps == nil {
		steps = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"steps": steps})
}

func getPendingApprovalsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	rows, err := dbPool.Query(c.Request.Context(), `
		SELECT a.id, a.task_id, a.step_number, a.requested_at, a.status, a.risk_level, a.action_summary, a.generated_code,
		       t.task_type, t.input, t.severity
		FROM approval_requests a
		JOIN agent_tasks t ON a.task_id = t.id
		WHERE t.tenant_id = $1 AND a.status = 'pending'
		ORDER BY a.requested_at DESC
	`, tenantID)
	if err != nil {
		respondInternalError(c, err, "query pending approvals")
		return
	}
	defer rows.Close()

	var approvals []map[string]interface{}
	for rows.Next() {
		var approvalID, taskID, approvalStatus, riskLevel, actionSummary, generatedCode, taskType string
		var stepNumber int
		var requestedAt time.Time
		var taskInput map[string]interface{}
		var severity *string

		if err := rows.Scan(&approvalID, &taskID, &stepNumber, &requestedAt, &approvalStatus, &riskLevel, &actionSummary, &generatedCode, &taskType, &taskInput, &severity); err != nil {
			log.Printf("Error scanning approval row: %v", err)
			continue
		}

		approval := map[string]interface{}{
			"id":             approvalID,
			"task_id":        taskID,
			"step_number":    stepNumber,
			"requested_at":   requestedAt,
			"status":         approvalStatus,
			"risk_level":     riskLevel,
			"action_summary": actionSummary,
			"generated_code": generatedCode,
			"task_type":      taskType,
			"prompt":         taskInput["prompt"],
			"severity":       severity,
		}
		approvals = append(approvals, approval)
	}

	if approvals == nil {
		approvals = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"approvals": approvals, "count": len(approvals)})
}

func decideApprovalHandler(c *gin.Context) {
	approvalID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.MustGet("user_id").(string)

	var req struct {
		Approved bool   `json:"approved"`
		Comment  string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the approval belongs to this tenant and is pending
	var taskID string
	var approvalStatus string
	err := dbPool.QueryRow(c.Request.Context(), `
		SELECT a.task_id, a.status 
		FROM approval_requests a 
		JOIN agent_tasks t ON a.task_id = t.id 
		WHERE a.id = $1 AND t.tenant_id = $2
	`, approvalID, tenantID).Scan(&taskID, &approvalStatus)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "approval not found"})
		return
	}

	if approvalStatus != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "approval already decided"})
		return
	}

	// Update the approval request
	decisionStatus := "rejected"
	if req.Approved {
		decisionStatus = "approved"
	}
	_, err = dbPool.Exec(c.Request.Context(),
		"UPDATE approval_requests SET status = $1, decided_at = NOW(), decided_by = $2, decision_comment = $3 WHERE id = $4",
		decisionStatus, userID, req.Comment, approvalID,
	)
	if err != nil {
		respondInternalError(c, err, "update approval record")
		return
	}

	// Send Temporal signal to the waiting workflow
	workflowID := "task-" + taskID
	signalPayload := map[string]interface{}{
		"approved":   req.Approved,
		"comment":    req.Comment,
		"decided_by": userID,
	}

	err = tc.SignalWorkflow(context.Background(), workflowID, "", "approval_decision", signalPayload)
	if err != nil {
		respondInternalError(c, err, "signal approval workflow")
		return
	}

	// Audit log
	action := "approval_approved"
	if !req.Approved {
		action = "approval_rejected"
	}
	_, _ = dbPool.Exec(c.Request.Context(),
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, action, "task", taskID, func() string { d, _ := json.Marshal(map[string]string{"approval_id": approvalID, "comment": req.Comment}); return string(d) }(),
	)

	c.JSON(http.StatusOK, gin.H{
		"status":      decisionStatus,
		"approval_id": approvalID,
		"task_id":     taskID,
	})
}

func getMeHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"user": map[string]interface{}{
			"id":        c.GetString("user_id"),
			"role":      c.GetString("user_role"),
			"tenant_id": c.GetString("tenant_id"),
		},
	})
}

func listSkillsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	rows, err := dbPool.Query(c.Request.Context(),
		"SELECT id, skill_name, skill_slug, threat_types, mitre_tactics, mitre_techniques, severity_default, investigation_methodology, detection_patterns, example_prompt, times_used, version, is_community, (code_template IS NOT NULL) as has_template FROM agent_skills WHERE is_active = true AND (tenant_id = $1 OR tenant_id IS NULL) ORDER BY times_used DESC",
		tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "query skills")
		return
	}
	defer rows.Close()

	var skills []map[string]interface{}
	for rows.Next() {
		var id, skillName, skillSlug, severityDefault, invMethodology, detPatterns, exPrompt string
		var threatTypes, mitreTactics, mitreTechniques []string
		var timesUsed, version int
		var isCommunity, hasTemplate bool

		if err := rows.Scan(&id, &skillName, &skillSlug, &threatTypes, &mitreTactics, &mitreTechniques, &severityDefault, &invMethodology, &detPatterns, &exPrompt, &timesUsed, &version, &isCommunity, &hasTemplate); err != nil {
			log.Printf("Error scanning skill row: %v", err)
			continue
		}

		skill := map[string]interface{}{
			"id":                        id,
			"skill_name":                skillName,
			"skill_slug":                skillSlug,
			"threat_types":              threatTypes,
			"mitre_tactics":             mitreTactics,
			"mitre_techniques":          mitreTechniques,
			"severity_default":          severityDefault,
			"investigation_methodology": invMethodology,
			"detection_patterns":        detPatterns,
			"example_prompt":            exPrompt,
			"times_used":                timesUsed,
			"version":                   version,
			"is_community":              isCommunity,
			"has_template":              hasTemplate,
		}
		skills = append(skills, skill)
	}

	if skills == nil {
		skills = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{"skills": skills, "count": len(skills)})
}

func getNotificationsHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	sinceStr := c.Query("since")
	var sinceTime time.Time
	if sinceStr != "" {
		parsed, err := time.Parse(time.RFC3339, sinceStr)
		if err == nil {
			sinceTime = parsed
		} else {
			sinceTime = time.Now().Add(-60 * time.Second)
		}
	} else {
		sinceTime = time.Now().Add(-60 * time.Second)
	}

	var notifications []map[string]interface{}

	// Fetch recent audit logs (completions, approvals)
	auditRows, err := dbPool.Query(c.Request.Context(), `
		SELECT action, resource_id, created_at 
		FROM agent_audit_log 
		WHERE tenant_id = $1 AND created_at > $2 AND action IN ('task_completed', 'approval_requested')
		ORDER BY created_at DESC LIMIT 20
	`, tenantID, sinceTime)

	if err == nil {
		defer auditRows.Close()
		for auditRows.Next() {
			var action, resID string
			var ts time.Time
			auditRows.Scan(&action, &resID, &ts)

			var message string
			if action == "task_completed" {
				message = fmt.Sprintf("Investigation completed: %s", resID[:8])
			} else if action == "approval_requested" {
				message = fmt.Sprintf("Approval required for investigation %s", resID[:8])
			}

			notifications = append(notifications, map[string]interface{}{
				"id":        uuid.New().String(),
				"type":      action,
				"message":   message,
				"task_id":   resID,
				"timestamp": ts,
			})
		}
	}

	// Fetch new SIEM alerts
	alertRows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, title, created_at 
		FROM siem_alerts 
		WHERE tenant_id = $1 AND created_at > $2 AND status = 'new'
		ORDER BY created_at DESC LIMIT 20
	`, tenantID, sinceTime)

	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var altID, title string
			var ts time.Time
			alertRows.Scan(&altID, &title, &ts)

			notifications = append(notifications, map[string]interface{}{
				"id":        altID,
				"type":      "siem_alert",
				"message":   fmt.Sprintf("New SIEM Alert: %s", title),
				"timestamp": ts,
			})
		}
	}

	if notifications == nil {
		notifications = []map[string]interface{}{}
	} else {
		sort.Slice(notifications, func(i, j int) bool {
			return notifications[i]["timestamp"].(time.Time).After(notifications[j]["timestamp"].(time.Time))
		})
	}

	c.JSON(http.StatusOK, gin.H{"notifications": notifications})
}

func getTaskTimelineHandler(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := c.MustGet("tenant_id").(string)

	var timeline []map[string]interface{}

	// 1. Fetch task creation and completion info
	var createdAt, completedAt *time.Time
	err := dbPool.QueryRow(c.Request.Context(),
		"SELECT created_at, completed_at FROM agent_tasks WHERE id = $1 AND tenant_id = $2", taskID, tenantID,
	).Scan(&createdAt, &completedAt)
	if err == nil && createdAt != nil {
		timeline = append(timeline, map[string]interface{}{
			"id":          "task-created",
			"timestamp":   *createdAt,
			"type":        "task_created",
			"icon":        "created",
			"description": "Investigation created",
		})
	}
	if err == nil && completedAt != nil {
		timeline = append(timeline, map[string]interface{}{
			"id":          "task-completed",
			"timestamp":   *completedAt,
			"type":        "task_completed",
			"icon":        "check",
			"description": "Investigation completed",
		})
	}

	// 2. Fetch steps
	stepRows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, step_number, step_type, summary_prompt, status, execution_ms, created_at
		FROM investigation_steps WHERE task_id = $1 ORDER BY created_at ASC
	`, taskID)
	if err == nil {
		defer stepRows.Close()
		for stepRows.Next() {
			var id, stepType, status string
			var stepNum int
			var prompt *string
			var execMs *int
			var ts time.Time
			stepRows.Scan(&id, &stepNum, &stepType, &prompt, &status, &execMs, &ts)

			desc := fmt.Sprintf("Step %d started: %s", stepNum, stepType)
			if prompt != nil && *prompt != "" {
				desc = fmt.Sprintf("Step %d started: %s", stepNum, *prompt)
			}

			timeline = append(timeline, map[string]interface{}{
				"id":          fmt.Sprintf("step-start-%s", id),
				"timestamp":   ts,
				"type":        "step_started",
				"icon":        "play",
				"description": desc,
			})

			if status == "completed" && execMs != nil {
				endTs := ts.Add(time.Duration(*execMs) * time.Millisecond)
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("step-end-%s", id),
					"timestamp":   endTs,
					"type":        "step_completed",
					"icon":        "check",
					"description": fmt.Sprintf("Step %d completed", stepNum),
					"duration_ms": *execMs,
				})
			} else if status == "failed" {
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("step-fail-%s", id),
					"timestamp":   ts,
					"type":        "step_failed",
					"icon":        "error",
					"description": fmt.Sprintf("Step %d failed", stepNum),
				})
			}
		}
	}

	// 3. Fetch audit logs (approvals, memory, skills)
	auditRows, err := dbPool.Query(c.Request.Context(), `
		SELECT id, action, details, created_at 
		FROM agent_audit_log WHERE tenant_id = $1 AND resource_type = 'task' AND resource_id = $2
	`, tenantID, taskID)
	if err == nil {
		defer auditRows.Close()
		for auditRows.Next() {
			var id, action string
			var details map[string]interface{}
			var ts time.Time
			auditRows.Scan(&id, &action, &details, &ts)

			// Only include specific actions in timeline
			if action == "approval_requested" || action == "approval_approved" || action == "approval_rejected" {
				desc := "Approval requested"
				icon := "alert"
				if action == "approval_approved" {
					desc = "Approval granted"
					icon = "check"
				} else if action == "approval_rejected" {
					desc = "Approval rejected"
					icon = "error"
				}
				if comment, ok := details["comment"].(string); ok {
					desc += fmt.Sprintf(": %s", comment)
				}
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("audit-%s", id),
					"timestamp":   ts,
					"type":        action,
					"icon":        icon,
					"description": desc,
				})
			} else if action == "skill_retrieved" {
				skillName := "unknown skill"
				if sn, ok := details["skill_name"].(string); ok {
					skillName = sn
				}
				timeline = append(timeline, map[string]interface{}{
					"id":          fmt.Sprintf("audit-%s", id),
					"timestamp":   ts,
					"type":        action,
					"icon":        "tool",
					"description": fmt.Sprintf("Retrieved skill: %s", skillName),
				})
			}
		}
	}

	if timeline == nil {
		timeline = []map[string]interface{}{}
	} else {
		sort.Slice(timeline, func(i, j int) bool {
			return timeline[i]["timestamp"].(time.Time).Before(timeline[j]["timestamp"].(time.Time))
		})
	}

	c.JSON(http.StatusOK, gin.H{"timeline": timeline})
}

// ============================================================
// BULK TASK CREATION (Issue #12)
// ============================================================

// BulkTaskRequest represents a single task in a bulk creation request.
type BulkTaskRequest struct {
	TaskType string                 `json:"task_type"`
	Input    map[string]interface{} `json:"input" binding:"required"`
}

// bulkCreateTasksHandler creates multiple tasks in a single request.
// POST /api/v1/tasks/bulk
func bulkCreateTasksHandler(c *gin.Context) {
	var req struct {
		Tasks []BulkTaskRequest `json:"tasks" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Tasks) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one task is required"})
		return
	}
	if len(req.Tasks) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 50 tasks per bulk request"})
		return
	}

	tenantID := c.MustGet("tenant_id").(string)

	// Validate all tasks first
	for i, task := range req.Tasks {
		if task.Input == nil || len(task.Input) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("task %d: input is required", i)})
			return
		}
		if task.TaskType == "" {
			req.Tasks[i].TaskType = "log_analysis"
		}
	}

	// Create all tasks in a transaction
	ctx := c.Request.Context()
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		respondInternalError(c, err, "begin bulk task transaction")
		return
	}
	defer tx.Rollback(ctx)

	var taskIDs []string
	var workflowIDs []string

	for _, task := range req.Tasks {
		taskID := uuid.New().String()
		taskIDs = append(taskIDs, taskID)

		_, err := tx.Exec(ctx,
			"INSERT INTO agent_tasks (id, tenant_id, task_type, input, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
			taskID, tenantID, task.TaskType, task.Input, "pending", time.Now(),
		)
		if err != nil {
			respondInternalError(c, err, "bulk create task")
			return
		}

		// Audit log
		_, _ = tx.Exec(ctx,
			"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id) VALUES ($1, $2, $3, $4)",
			tenantID, "task_created", "task", taskID,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		respondInternalError(c, err, "commit bulk task transaction")
		return
	}

	// Start workflows for all tasks (outside transaction)
	for i, task := range req.Tasks {
		taskID := taskIDs[i]
		workflowOptions := client.StartWorkflowOptions{
			ID:        "task-" + taskID,
			TaskQueue: "hydra-tasks",
		}

		we, err := tc.ExecuteWorkflow(context.Background(), workflowOptions, "ExecuteTaskWorkflow",
			TaskRequest{TaskType: task.TaskType, Input: task.Input})
		if err != nil {
			log.Printf("Failed to start workflow for bulk task %s: %v", taskID, err)
			_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
			workflowIDs = append(workflowIDs, "")
			continue
		}
		workflowIDs = append(workflowIDs, we.GetID())
	}

	// Build response
	var results []map[string]interface{}
	for i, taskID := range taskIDs {
		wfID := ""
		if i < len(workflowIDs) {
			wfID = workflowIDs[i]
		}
		status := "pending"
		if wfID == "" {
			status = "failed"
		}
		results = append(results, map[string]interface{}{
			"task_id":     taskID,
			"workflow_id": wfID,
			"status":      status,
		})
	}

	c.JSON(http.StatusCreated, gin.H{
		"tasks":   results,
		"created": len(taskIDs),
	})
}
