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
// LAYER 1: PRE-TEMPORAL REDIS DEDUP
//
// Mirrors the Python dedup logic in worker/stages/ingest.py:166-188.
// Prevents duplicate alerts from creating redundant Temporal workflows.
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
	"critical": 60,
	"high":     300,
	"medium":   900,
	"low":      3600,
	"info":     7200,
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
//
// Python uses: json.dumps(canonical, sort_keys=True).encode()
// Go json.Marshal sorts map keys alphabetically — same behavior.
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

// checkPreDedup checks if an identical alert was already submitted recently.
// Returns (isDuplicate, existingTaskID).
// Fail-open: returns (false, "") if Redis is unavailable.
func checkPreDedup(ctx context.Context, taskType string, input map[string]interface{}) (bool, string) {
	if !apiDedupEnabled || redisClient == nil {
		return false, ""
	}

	hash := computeAlertHash(input)
	key := "dedup:exact:" + hash

	existing, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		// Key not found or Redis error — not a duplicate
		return false, ""
	}

	log.Printf("[DEDUP] Pre-Temporal dedup hit: hash=%s existing_task=%s", hash[:16], existing)
	return true, existing
}

// registerPreDedup registers an alert hash in Redis after the workflow is created.
// This makes subsequent identical alerts get deduplicated.
func registerPreDedup(ctx context.Context, taskType string, input map[string]interface{}, taskID, severity string) {
	if !apiDedupEnabled || redisClient == nil {
		return
	}

	hash := computeAlertHash(input)
	key := "dedup:exact:" + hash

	sev := strings.ToLower(severity)
	ttl, ok := dedupTTL[sev]
	if !ok {
		ttl = 300 // default to "high" TTL
	}

	err := redisClient.SetEx(ctx, key, taskID, time.Duration(ttl)*time.Second).Err()
	if err != nil {
		log.Printf("[DEDUP] Failed to register dedup key: %v", err)
	}
}
