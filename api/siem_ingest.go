package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
)

// ============================================================
// SIEM INGEST ENDPOINTS — Splunk HEC + Elastic SIEM
// ============================================================

// mapAlertToTaskType maps a SIEM alert signature/rule name to a ZOVARK task type
// using regex patterns. Falls back to a sanitized version of the signature.
func mapAlertToTaskType(signature string) string {
	sig := strings.ToLower(signature)
	patterns := map[string]string{
		`brute.?force|failed.?password|multiple.?login`:  "brute_force",
		`malware|trojan|ransomware`:                      "ransomware_triage",
		`beacon|c2|command.?and.?control`:                "network_beaconing",
		`phish|credential.?harvest`:                      "phishing",
		`lateral.?movement|pass.?the.?hash|pth`:          "lateral_movement",
		`exfil|large.?transfer|dns.?tunnel`:              "data_exfiltration",
		`privilege.?escalat|sudo|uac`:                    "privilege_escalation",
		`insider|unauthorized.?access`:                   "insider_threat",
		`sql.?inject|xss|cross.?site|command.?inject`:    "web_attack",
		`denial.?of.?service|ddos|dos`:                   "dos_attack",
		`suspicious.?process|fileless|powershell.?abuse`: "endpoint_anomaly",
	}
	for pattern, taskType := range patterns {
		if matched, _ := regexp.MatchString(pattern, sig); matched {
			return taskType
		}
	}
	// Default: sanitize the signature as task_type
	sanitized := strings.ToLower(strings.ReplaceAll(signature, " ", "_"))
	sanitized = regexp.MustCompile(`[^a-z0-9_]`).ReplaceAllString(sanitized, "")
	if sanitized == "" {
		return "log_analysis"
	}
	// Truncate to reasonable length
	if len(sanitized) > 60 {
		sanitized = sanitized[:60]
	}
	return sanitized
}

// createIngestTask builds agent_tasks.input (envelope + OCSF siem_event), stores raw_input as exact bytes (valid JSON for JSONB),
// writes API-computed dedup_hash, then runs dedup / batch / Temporal like other ingest paths.
// rawInputJSON must be valid UTF-8 JSON for the raw_input JSONB column (JSON bodies: wire copy; CEF/LEEF: json.Marshal(line)).
func createIngestTask(ctx context.Context, tenantID, taskType, prompt, source string, rawInputJSON []byte, ocsfEvent map[string]interface{}, envelope map[string]interface{}) (taskIDOut string, traceIDOut string, err error) {
	taskID := uuid.New().String()
	traceID := zovarkTraceUUIDFromContext(ctx)

	input := map[string]interface{}{}
	for k, v := range envelope {
		input[k] = v
	}
	input["siem_event"] = ocsfEvent
	input["prompt"] = prompt
	input["ingest_source"] = source
	input["trace_id"] = traceID

	severity := "medium"
	if s, ok := input["severity"].(string); ok && s != "" {
		severity = s
	}

	if len(rawInputJSON) == 0 {
		rawInputJSON = []byte("null")
	}
	dedupHash := computeDedupHash(input)

	// --- Layer 1: Pre-Temporal Redis Dedup ---
	if isDup, existingID := checkPreDedup(ctx, taskType, input); isDup {
		dbCtx, dbCancel := dbContextWithTimeout(ctx)
		defer dbCancel()
		_, _ = dbPool.Exec(dbCtx,
			`INSERT INTO agent_tasks (id, tenant_id, task_type, input, raw_input, dedup_hash, status, created_at, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			taskID, tenantID, taskType, input, rawInputJSON, dedupHash, "deduplicated", time.Now(), traceID,
		)
		slog.InfoContext(ctx, "ingest_dedup_duplicate",
			slog.String("outcome", "deduplicated"),
			slog.String("ingest.task_id", taskID),
			slog.String("ingest.existing_task_id", existingID),
			slog.String("ingest.source", source),
			slog.String("ingest.task_type", taskType),
		)
		return existingID, "", nil
	}

	// --- Layer 2: Pre-Temporal Batch Buffer ---
	sourceIP := SourceIPFromTaskInput(input)
	destIP := DestIPFromTaskInput(input)

	if shouldSkip, batchParentID := tryBatchAlert(ctx, taskType, sourceIP, destIP, severity, taskID); shouldSkip {
		dbCtx, dbCancel := dbContextWithTimeout(ctx)
		defer dbCancel()
		_, _ = dbPool.Exec(dbCtx,
			`INSERT INTO agent_tasks (id, tenant_id, task_type, input, raw_input, dedup_hash, status, created_at, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			taskID, tenantID, taskType, input, rawInputJSON, dedupHash, "batched", time.Now(), traceID,
		)
		slog.InfoContext(ctx, "ingest_batch_absorbed",
			slog.String("outcome", "batched"),
			slog.String("ingest.task_id", taskID),
			slog.String("ingest.batch_parent_id", batchParentID),
			slog.String("ingest.source", source),
			slog.String("ingest.task_type", taskType),
		)
		return batchParentID, "", nil
	}

	// Insert task inside explicit transaction
	// CRITICAL: tx.Commit() MUST happen BEFORE ExecuteWorkflow() to avoid race condition
	dbCtx, dbCancel := dbContextWithTimeout(ctx)
	tx, err := beginTenantTx(dbCtx, tenantID)
	if err != nil {
		dbCancel()
		return "", "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(dbCtx) // no-op after commit

	_, err = tx.Exec(dbCtx,
		`INSERT INTO agent_tasks (id, tenant_id, task_type, input, raw_input, dedup_hash, status, created_at, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		taskID, tenantID, taskType, input, rawInputJSON, dedupHash, "pending", time.Now(), traceID,
	)
	if err != nil {
		dbCancel()
		if isLockTimeout(err) {
			HandlePostgresLock(nil, tenantID, taskID, severity, "INSERT", "agent_tasks", 5000)
		}
		return "", "", fmt.Errorf("failed to create task: %w", err)
	}

	// Audit log (inside same transaction)
	auditDetails, _ := json.Marshal(map[string]string{
		"task_id":       taskID,
		"ingest_source": source,
		"task_type":     taskType,
	})
	_, _ = tx.Exec(dbCtx,
		"INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)",
		tenantID, "task_created", "task", taskID,
		string(auditDetails),
	)

	// COMMIT — data now visible to all connections (including worker's fetch_task)
	if err := tx.Commit(dbCtx); err != nil {
		dbCancel()
		return "", "", fmt.Errorf("failed to commit task transaction: %w", err)
	}
	dbCancel()

	// Register dedup hash AFTER commit so subsequent alerts get deduplicated
	registerPreDedup(ctx, taskType, input, taskID, severity)

	// --- Layer 3: Temporal Backpressure ---
	allowed, depth := checkBackpressure(ctx)
	if !allowed {
		if isHardLimitReached(depth) {
			// Hard limit — mark as failed, caller should return 503
			_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
			return "", "", fmt.Errorf("backpressure hard limit reached (depth=%d)", depth)
		}
		// Soft limit — queue for later processing by drain goroutine
		_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'queued' WHERE id = $1", taskID)
		slog.WarnContext(ctx, "ingest_backpressure_queued",
			slog.String("outcome", "queued"),
			slog.String("ingest.task_id", taskID),
			slog.Int("backpressure.depth", depth),
			slog.String("ingest.source", source),
		)
		return taskID, traceID, nil
	}

	// Publish to Redpanda — worker consumes tasks.new.{tenant_id} and starts Temporal
	pubCtx, pubCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pubCancel()
	if err := publishTaskNew(pubCtx, tenantID, taskID, taskType, input); err != nil {
		_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
		return "", "", fmt.Errorf("failed to publish task to redpanda: %w", err)
	}

	recordWorkflowStart(ctx, "task-"+taskID)

	return taskID, traceID, nil
}

// ============================================================
// POST /api/v1/ingest/splunk — Splunk HEC format receiver
// ============================================================
//
// Accepts Splunk HTTP Event Collector (HEC) format:
//
//	{
//	  "time": 1234567890,
//	  "event": {"signature": "...", "src_ip": "...", "dest_ip": "...", "user": "...", "raw": "..."},
//	  "sourcetype": "linux:syslog",
//	  "source": "syslog",
//	  "host": "web01"
//	}
func splunkIngestHandler(c *gin.Context) {
	ctx, sp := otel.Tracer("zovark-api").Start(c.Request.Context(), "ingest.splunk")
	defer sp.End()
	c.Request = c.Request.WithContext(ctx)

	tenantID := c.MustGet("tenant_id").(string)

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	var payload struct {
		Time       float64                `json:"time"`
		Event      map[string]interface{} `json:"event"`
		SourceType string                 `json:"sourcetype"`
		Source     string                 `json:"source"`
		Host       string                 `json:"host"`
		Index      string                 `json:"index"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload: " + err.Error()})
		return
	}

	if payload.Event == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required field: event"})
		return
	}

	rawCopy := append([]byte(nil), body...)

	ocsf := NormalizeSplunkHEC(payload.Event, payload.SourceType, payload.Host, payload.Source)

	signature := ""
	if sig, ok := payload.Event["signature"].(string); ok {
		signature = sig
	} else if sig, ok := payload.Event["alert_name"].(string); ok {
		signature = sig
	} else if sig, ok := payload.Event["name"].(string); ok {
		signature = sig
	} else {
		signature = payload.SourceType
	}

	taskType := mapAlertToTaskType(sanitizeSIEMField(signature, 200))

	sourceIP := ""
	if v, ok := payload.Event["src_ip"].(string); ok {
		sourceIP = v
	} else if v, ok := payload.Event["source_ip"].(string); ok {
		sourceIP = v
	}
	destIP := ""
	if v, ok := payload.Event["dest_ip"].(string); ok {
		destIP = v
	} else if v, ok := payload.Event["destination_ip"].(string); ok {
		destIP = v
	}

	severity := "medium"
	if v, ok := payload.Event["severity"].(string); ok && v != "" {
		severity = v
	}

	user := ""
	if v, ok := payload.Event["user"].(string); ok {
		user = v
	}

	prompt := fmt.Sprintf(
		"Investigate Splunk alert: %s. Source: %s, Dest: %s. User: %s. Sourcetype: %s. Severity: %s.",
		sanitizeSIEMField(signature, 200),
		sanitizeSIEMField(sourceIP, 45),
		sanitizeSIEMField(destIP, 45),
		sanitizeSIEMField(user, 100),
		sanitizeSIEMField(payload.SourceType, 100),
		sanitizeSIEMField(severity, 20),
	)

	// FIX #5: sanitize all string values in siem_event before storing
	envelope := map[string]interface{}{
		"severity":    severity,
		"source_ip":   sourceIP,
		"dest_ip":     destIP,
		"user":        user,
		"sourcetype":  payload.SourceType,
		"host":        payload.Host,
		"siem_vendor": "splunk",
		"siem_event":  sanitizeSIEMMap(payload.Event),
	}
	if raw, ok := payload.Event["raw"].(string); ok {
		envelope["log_data"] = sanitizeSIEMField(raw, 10000)
	}

	taskID, _, err := createIngestTask(ctx, tenantID, taskType, prompt, "splunk_hec", rawCopy, ocsf, envelope)
	if err != nil {
		slog.ErrorContext(ctx, "ingest_splunk_failed",
			slog.String("outcome", "error"),
			slog.String("tenant_id", tenantID),
			slog.String("ingest.vendor", "splunk_hec"),
			slog.Any("error", err),
		)
		respondInternalError(c, err, "splunk ingest task creation")
		return
	}
	recordAPIIngest(ctx, "splunk_hec")

	c.JSON(http.StatusOK, gin.H{
		"task_id": taskID,
		"status":  "queued",
		"source":  "splunk_hec",
	})
}

// ============================================================
// POST /api/v1/ingest/elastic — Elastic SIEM alert format
// ============================================================
//
// Accepts Elastic Security alert format:
//
//	{
//	  "rule": {"name": "...", "severity": "...", "id": "...", "description": "..."},
//	  "source": {"ip": "..."},
//	  "destination": {"ip": "..."},
//	  "user": {"name": "..."},
//	  "message": "...",
//	  "host": {"name": "..."},
//	  "event": {"action": "...", "category": "..."}
//	}
func elasticIngestHandler(c *gin.Context) {
	ctx, sp := otel.Tracer("zovark-api").Start(c.Request.Context(), "ingest.elastic")
	defer sp.End()
	c.Request = c.Request.WithContext(ctx)

	tenantID := c.MustGet("tenant_id").(string)

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload: " + err.Error()})
		return
	}

	ruleName := ""
	severity := "medium"
	ruleDescription := ""
	if ruleObj, ok := payload["rule"].(map[string]interface{}); ok {
		if v, ok := ruleObj["name"].(string); ok {
			ruleName = v
		}
		if v, ok := ruleObj["severity"].(string); ok && v != "" {
			severity = v
		}
		if v, ok := ruleObj["description"].(string); ok {
			ruleDescription = v
		}
	}

	if ruleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required field: rule.name"})
		return
	}

	taskType := mapAlertToTaskType(sanitizeSIEMField(ruleName, 200))

	rawCopy := append([]byte(nil), body...)

	ocsf := NormalizeElasticECS(payload)

	sourceIP := ""
	if srcObj, ok := payload["source"].(map[string]interface{}); ok {
		if v, ok := srcObj["ip"].(string); ok {
			sourceIP = v
		}
	}
	destIP := ""
	if dstObj, ok := payload["destination"].(map[string]interface{}); ok {
		if v, ok := dstObj["ip"].(string); ok {
			destIP = v
		}
	}
	user := ""
	if userObj, ok := payload["user"].(map[string]interface{}); ok {
		if v, ok := userObj["name"].(string); ok {
			user = v
		}
	}
	host := ""
	if hostObj, ok := payload["host"].(map[string]interface{}); ok {
		if v, ok := hostObj["name"].(string); ok {
			host = v
		}
	}
	message := ""
	if v, ok := payload["message"].(string); ok {
		message = v
	}

	prompt := fmt.Sprintf(
		"Investigate Elastic SIEM alert: %s. Source: %s, Dest: %s. User: %s. Host: %s. Severity: %s. %s",
		sanitizeSIEMField(ruleName, 200),
		sanitizeSIEMField(sourceIP, 45),
		sanitizeSIEMField(destIP, 45),
		sanitizeSIEMField(user, 100),
		sanitizeSIEMField(host, 100),
		sanitizeSIEMField(severity, 20),
		sanitizeSIEMField(ruleDescription, 300),
	)

	// FIX #5: sanitize all string values in siem_event before storing
	envelope := map[string]interface{}{
		"severity":         severity,
		"source_ip":        sourceIP,
		"dest_ip":          destIP,
		"user":             user,
		"host":             host,
		"rule_name":        ruleName,
		"rule_description": ruleDescription,
		"siem_vendor":      "elastic",
		"siem_event":       sanitizeSIEMMap(payload),
	}
	if message != "" {
		envelope["log_data"] = sanitizeSIEMField(message, 10000)
	}

	taskID, _, err := createIngestTask(ctx, tenantID, taskType, prompt, "elastic_siem", rawCopy, ocsf, envelope)
	if err != nil {
		slog.ErrorContext(ctx, "ingest_elastic_failed",
			slog.String("outcome", "error"),
			slog.String("tenant_id", tenantID),
			slog.String("ingest.vendor", "elastic_siem"),
			slog.Any("error", err),
		)
		respondInternalError(c, err, "elastic ingest task creation")
		return
	}
	recordAPIIngest(ctx, "elastic_siem")

	c.JSON(http.StatusOK, gin.H{
		"task_id": taskID,
		"status":  "queued",
		"source":  "elastic_siem",
	})
}

// ============================================================
// POST /api/v1/ingest/cef — ArcSight CEF (single line, text/plain or raw body)
// ============================================================

func cefIngestHandler(c *gin.Context) {
	ctx, sp := otel.Tracer("zovark-api").Start(c.Request.Context(), "ingest.cef")
	defer sp.End()
	c.Request = c.Request.WithContext(ctx)

	tenantID := c.MustGet("tenant_id").(string)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	line := strings.TrimSpace(string(body))
	if line == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty body"})
		return
	}
	ocsf, err := ParseCEF(line)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CEF: " + err.Error()})
		return
	}
	rule := ""
	if r, ok := ocsf["rule_name"].(string); ok {
		rule = r
	}
	taskType := mapAlertToTaskType(sanitizeSIEMField(rule, 200))
	sev := "medium"
	if s, ok := ocsf["severity"].(string); ok && s != "" {
		sev = s
	}
	src := SourceIPFromTaskInput(map[string]interface{}{"siem_event": ocsf})
	dst := DestIPFromTaskInput(map[string]interface{}{"siem_event": ocsf})
	prompt := fmt.Sprintf("Investigate CEF alert: %s. Source: %s. Dest: %s. Severity: %s.",
		sanitizeSIEMField(rule, 200), sanitizeSIEMField(src, 45), sanitizeSIEMField(dst, 45), sanitizeSIEMField(sev, 20))
	rawJSON, jerr := json.Marshal(line)
	if jerr != nil {
		respondInternalError(c, jerr, "marshal cef raw_input")
		return
	}
	envelope := map[string]interface{}{
		"severity":    sev,
		"source_ip":   src,
		"dest_ip":     dst,
		"siem_vendor": "arcsight_cef",
	}
	taskID, _, err := createIngestTask(ctx, tenantID, taskType, prompt, "arcsight_cef", rawJSON, ocsf, envelope)
	if err != nil {
		slog.ErrorContext(ctx, "ingest_cef_failed",
			slog.String("outcome", "error"),
			slog.String("tenant_id", tenantID),
			slog.String("ingest.vendor", "arcsight_cef"),
			slog.Any("error", err),
		)
		respondInternalError(c, err, "cef ingest task creation")
		return
	}
	recordAPIIngest(ctx, "arcsight_cef")
	c.JSON(http.StatusOK, gin.H{"task_id": taskID, "status": "queued", "source": "arcsight_cef"})
}

// ============================================================
// POST /api/v1/ingest/leef — QRadar LEEF (single line)
// ============================================================

func leefIngestHandler(c *gin.Context) {
	ctx, sp := otel.Tracer("zovark-api").Start(c.Request.Context(), "ingest.leef")
	defer sp.End()
	c.Request = c.Request.WithContext(ctx)

	tenantID := c.MustGet("tenant_id").(string)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	line := strings.TrimSpace(string(body))
	if line == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty body"})
		return
	}
	ocsf, err := ParseLEEF(line)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid LEEF: " + err.Error()})
		return
	}
	rule := ""
	if r, ok := ocsf["rule_name"].(string); ok {
		rule = r
	}
	taskType := mapAlertToTaskType(sanitizeSIEMField(rule, 200))
	sev := "medium"
	if s, ok := ocsf["severity"].(string); ok && s != "" {
		sev = s
	}
	src := SourceIPFromTaskInput(map[string]interface{}{"siem_event": ocsf})
	dst := DestIPFromTaskInput(map[string]interface{}{"siem_event": ocsf})
	prompt := fmt.Sprintf("Investigate LEEF alert: %s. Source: %s. Dest: %s. Severity: %s.",
		sanitizeSIEMField(rule, 200), sanitizeSIEMField(src, 45), sanitizeSIEMField(dst, 45), sanitizeSIEMField(sev, 20))
	rawJSON, jerr := json.Marshal(line)
	if jerr != nil {
		respondInternalError(c, jerr, "marshal leef raw_input")
		return
	}
	envelope := map[string]interface{}{
		"severity":    sev,
		"source_ip":   src,
		"dest_ip":     dst,
		"siem_vendor": "qradar_leef",
	}
	taskID, _, err := createIngestTask(ctx, tenantID, taskType, prompt, "qradar_leef", rawJSON, ocsf, envelope)
	if err != nil {
		slog.ErrorContext(ctx, "ingest_leef_failed",
			slog.String("outcome", "error"),
			slog.String("tenant_id", tenantID),
			slog.String("ingest.vendor", "qradar_leef"),
			slog.Any("error", err),
		)
		respondInternalError(c, err, "leef ingest task creation")
		return
	}
	recordAPIIngest(ctx, "qradar_leef")
	c.JSON(http.StatusOK, gin.H{"task_id": taskID, "status": "queued", "source": "qradar_leef"})
}

// ============================================================
// GET /api/v1/ingest/health — Connector health check
// ============================================================

func ingestHealthHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Count recent ingested tasks by source
	type sourceCount struct {
		Source string
		Count  int
		Last   *time.Time
	}

	var splunkCount, elasticCount int
	var splunkLast, elasticLast *time.Time

	// Splunk ingest stats
	_ = dbPool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*), MAX(created_at) FROM agent_tasks
		 WHERE tenant_id = $1 AND input->>'ingest_source' = 'splunk_hec'
		 AND created_at > NOW() - INTERVAL '24 hours'`,
		tenantID,
	).Scan(&splunkCount, &splunkLast)

	// Elastic ingest stats
	_ = dbPool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*), MAX(created_at) FROM agent_tasks
		 WHERE tenant_id = $1 AND input->>'ingest_source' = 'elastic_siem'
		 AND created_at > NOW() - INTERVAL '24 hours'`,
		tenantID,
	).Scan(&elasticCount, &elasticLast)

	// Last 5 ingested alerts
	rows, err := dbPool.Query(c.Request.Context(),
		`SELECT id, task_type, status, input->>'ingest_source' AS source, created_at
		 FROM agent_tasks
		 WHERE tenant_id = $1 AND input->>'ingest_source' IS NOT NULL
		 ORDER BY created_at DESC LIMIT 5`,
		tenantID,
	)

	var recentAlerts []map[string]interface{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, taskType, status string
			var source *string
			var createdAt time.Time
			if err := rows.Scan(&id, &taskType, &status, &source, &createdAt); err != nil {
				slog.WarnContext(c.Request.Context(), "ingest_health_scan_row_failed",
					slog.String("outcome", "warning"),
					slog.String("tenant_id", tenantID),
					slog.Any("error", err),
				)
				continue
			}
			recentAlerts = append(recentAlerts, map[string]interface{}{
				"task_id":    id,
				"task_type":  taskType,
				"status":     status,
				"source":     source,
				"created_at": createdAt,
			})
		}
	}

	if recentAlerts == nil {
		recentAlerts = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"connectors": gin.H{
			"splunk_hec": gin.H{
				"endpoint":      "/api/v1/ingest/splunk",
				"alerts_24h":    splunkCount,
				"last_received": splunkLast,
				"status":        connectorStatus(splunkCount, splunkLast),
			},
			"elastic_siem": gin.H{
				"endpoint":      "/api/v1/ingest/elastic",
				"alerts_24h":    elasticCount,
				"last_received": elasticLast,
				"status":        connectorStatus(elasticCount, elasticLast),
			},
		},
		"recent_alerts": recentAlerts,
	})
}

// connectorStatus returns a status string based on recent activity.
func connectorStatus(count24h int, lastReceived *time.Time) string {
	if count24h == 0 {
		return "idle"
	}
	if lastReceived != nil && time.Since(*lastReceived) < 1*time.Hour {
		return "active"
	}
	return "stale"
}
