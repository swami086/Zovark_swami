package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// ============================================================
// LAYER 1: PRE-TEMPORAL REDIS DEDUP (v2 — investigation-aware)
//
// Mirrors the Python dedup logic in worker/stages/ingest.py:166-188.
// Prevents duplicate alerts from creating redundant Temporal workflows.
//
// v2 changes (from blind TTL):
//   - Stores structured JSON entries (task_id, status, severity, verdict)
//   - Allows retry when previous investigation failed/errored
//   - Allows escalation when new alert has higher severity
//   - Worker updates entry on completion (via store.py)
//
// Fail-open: if Redis is unavailable, skip dedup and proceed normally.
// ============================================================

var apiDedupEnabled = true

func init() {
	if v := os.Getenv("ZOVARK_API_DEDUP_ENABLED"); v == "false" {
		apiDedupEnabled = false
	}
}

// Timestamp patterns to normalize (must match Python exactly)
var timestampPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?`),
	regexp.MustCompile(`\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}`),
}

// Severity-based TTLs (in seconds) — must match Python DEDUP_TTL
var dedupTTL = map[string]int{
	"critical": 900,  // 15 min — active incidents produce sustained identical alerts
	"high":     600,  // 10 min
	"medium":   300,  // 5 min
	"low":      3600, // 1 hour
	"info":     7200, // 2 hours
}

// DedupEntry is the structured value stored in Redis for v2 dedup.
type DedupEntry struct {
	TaskID    string `json:"task_id"`
	Status    string `json:"status"`    // pending | completed | failed | error
	Verdict   string `json:"verdict"`   // empty if not yet completed
	RiskScore int    `json:"risk_score"`
	Severity  string `json:"severity"`  // severity of original alert
	CreatedAt string `json:"created_at"`
}

// normalizeRawLog strips timestamps from raw_log for dedup hashing.
// Matches Python _normalize_raw_log() exactly.
func normalizeRawLog(raw string) string {
	for _, p := range timestampPatterns {
		raw = p.ReplaceAllString(raw, "TIMESTAMP")
	}
	return raw
}

// computeAlertHash computes a SHA-256 hash of the canonical alert fields.
// Must produce identical output to Python _compute_alert_hash().
func computeAlertHash(input map[string]interface{}) string {
	// Extract siem_event fields (the alert data lives here for API-submitted tasks)
	siem := input
	if se, ok := input["siem_event"].(map[string]interface{}); ok {
		siem = se
	}

	// Build canonical dict with exact same 6 fields as Python
	canonical := map[string]string{
		"destination_ip": getStringField(siem, "destination_ip", "dest_ip"),
		"hostname":       getStringField(siem, "hostname"),
		"raw_log":        normalizeRawLog(getStringField(siem, "raw_log")),
		"rule_name":      getStringField(siem, "rule_name"),
		"source_ip":      getStringField(siem, "source_ip"),
		"username":       getStringField(siem, "username"),
	}

	data, _ := json.Marshal(canonical)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// getStringField extracts a string from a map, trying multiple key names.
func getStringField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v
		}
	}
	return ""
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// checkPreDedup checks if an identical alert was already submitted recently.
// Returns (isDuplicate, existingTaskID, reason).
// Fail-open: returns (false, "", "redis_error") if Redis is unavailable.
func checkPreDedup(ctx context.Context, taskType string, input map[string]interface{}) (bool, string) {
	if !apiDedupEnabled || redisClient == nil {
		return false, ""
	}

	hash := computeAlertHash(input)
	key := "dedup:exact:" + hash

	val, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		// Key not found or Redis error — not a duplicate
		return false, ""
	}

	// Try to parse as v2 JSON entry
	var entry DedupEntry
	if err := json.Unmarshal([]byte(val), &entry); err != nil {
		// Old v1 plain-string entry — treat as duplicate with existing task_id
		log.Printf("[DEDUP] Pre-Temporal dedup hit (v1): hash=%s existing_task=%s", hash[:16], val)
		return true, val
	}

	// v2 structured entry — apply investigation-aware logic
	newSeverity := getInputSeverity(input)

	// Case 1: Previous investigation FAILED — allow retry
	if entry.Status == "error" || entry.Status == "failed" {
		log.Printf("[DEDUP] Retry after failure: hash=%s old_task=%s old_status=%s", hash[:16], entry.TaskID, entry.Status)
		redisClient.Del(ctx, key)
		recordDedupDecision(ctx, "retry_after_failure")
		return false, ""
	}

	// Case 2: New alert is HIGHER severity — escalation bypass
	if severityRank(newSeverity) > severityRank(entry.Severity) {
		log.Printf("[DEDUP] Severity escalation: hash=%s %s→%s old_task=%s", hash[:16], entry.Severity, newSeverity, entry.TaskID)
		recordDedupDecision(ctx, "severity_escalation")
		return false, ""
	}

	// Case 3: Normal duplicate — dedup
	log.Printf("[DEDUP] Pre-Temporal dedup hit (v2): hash=%s existing_task=%s status=%s", hash[:16], entry.TaskID, entry.Status)
	recordDedupDecision(ctx, "deduplicated")
	return true, entry.TaskID
}

// registerPreDedup registers an alert hash in Redis after the workflow is created.
// Uses v2 structured JSON entry.
func registerPreDedup(ctx context.Context, taskType string, input map[string]interface{}, taskID, severity string) {
	if !apiDedupEnabled || redisClient == nil {
		return
	}

	hash := computeAlertHash(input)
	key := "dedup:exact:" + hash

	entry := DedupEntry{
		TaskID:    taskID,
		Status:    "pending",
		Severity:  strings.ToLower(severity),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(entry)

	sev := strings.ToLower(severity)
	ttl, ok := dedupTTL[sev]
	if !ok {
		ttl = 300
	}

	err := redisClient.SetEx(ctx, key, string(data), time.Duration(ttl)*time.Second).Err()
	if err != nil {
		log.Printf("[DEDUP] Failed to register dedup key: %v", err)
	}

	recordDedupDecision(ctx, "new_alert")
}

// getInputSeverity extracts severity from the task input.
func getInputSeverity(input map[string]interface{}) string {
	if s, ok := input["severity"].(string); ok {
		return strings.ToLower(s)
	}
	return "medium"
}

// clearDedupEntry removes a dedup entry (used by force_reinvestigate).
func clearDedupEntry(ctx context.Context, input map[string]interface{}) {
	if redisClient == nil {
		return
	}
	hash := computeAlertHash(input)
	key := "dedup:exact:" + hash
	redisClient.Del(ctx, key)
}

// recordDedupDecision increments a Redis counter for observability.
func recordDedupDecision(ctx context.Context, decision string) {
	if redisClient == nil {
		return
	}
	key := "dedup:stats:" + decision
	redisClient.Incr(ctx, key)
	redisClient.Expire(ctx, key, 1*time.Hour)
}
