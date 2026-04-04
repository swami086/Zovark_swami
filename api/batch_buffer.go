package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// ============================================================
// LAYER 2: PRE-TEMPORAL BATCH BUFFER
//
// Groups similar alerts by (task_type, source_ip) within a short
// time window. First alert creates the workflow; subsequent alerts
// within the window are absorbed (no workflow created).
//
// Uses Redis atomic operations (Lua script) to prevent race conditions.
// Fail-open: if Redis is unavailable, create workflow normally.
// ============================================================

var (
	apiBatchEnabled       = true
	apiBatchWindowSeconds = 5.0
	apiBatchMaxSize       = 500
)

func init() {
	if v := os.Getenv("ZOVARK_API_BATCH_ENABLED"); v == "false" {
		apiBatchEnabled = false
	}
	if v := os.Getenv("ZOVARK_API_BATCH_WINDOW_SECONDS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			apiBatchWindowSeconds = f
		}
	}
	if v := os.Getenv("ZOVARK_API_BATCH_MAX_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			apiBatchMaxSize = n
		}
	}
}

// Severity-based window multipliers (must match Python smart_batcher.py)
var severityMultiplier = map[string]float64{
	"critical": 0.25,
	"high":     0.5,
	"medium":   1.0,
	"low":      2.0,
	"info":     3.0,
}

// Lua script for atomic batch check-and-increment with severity promotion.
// Returns 0 if this is the first alert (proceed with workflow).
// Returns 1 if absorbed into existing batch (skip workflow).
// Returns 2 if batch is full or window expired (proceed with new workflow).
// Severity promotion: if new alert has higher severity, replace batch representative.
//
// Window expiry uses the ORIGINAL batch window (stored in 'window' field), not the
// current alert's severity-adjusted window. This ensures a critical alert arriving
// within the original batch window gets promoted rather than starting a new batch.
const batchLuaScript = `
local key = KEYS[1]
local task_id = ARGV[1]
local now_ts = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local max_size = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local severity = ARGV[6]

-- Severity ranking for promotion comparison
local sev_rank = {critical=5, high=4, medium=3, low=2, info=1}
local new_rank = sev_rank[severity] or 0

local exists = redis.call('EXISTS', key)
if exists == 0 then
    -- First alert: start new batch, store the initial window for future expiry checks
    redis.call('HSET', key, 'task_id', task_id, 'count', 1, 'first_ts', tostring(now_ts), 'severity', severity, 'window', tostring(window))
    redis.call('EXPIRE', key, ttl)
    return {0, task_id, 1}
end

-- Batch exists: check window and size
local first_ts = tonumber(redis.call('HGET', key, 'first_ts'))
local count = tonumber(redis.call('HGET', key, 'count'))
local batch_task_id = redis.call('HGET', key, 'task_id')
local batch_severity = redis.call('HGET', key, 'severity') or 'info'
-- Use the ORIGINAL batch window for expiry, not the current alert's window
local batch_window = tonumber(redis.call('HGET', key, 'window') or tostring(window))

if (now_ts - first_ts) > batch_window or count >= max_size then
    -- Window expired or batch full: start new batch
    redis.call('DEL', key)
    redis.call('HSET', key, 'task_id', task_id, 'count', 1, 'first_ts', tostring(now_ts), 'severity', severity, 'window', tostring(window))
    redis.call('EXPIRE', key, ttl)
    return {2, task_id, 1}
end

-- Within window and under max: absorb this alert
local new_count = redis.call('HINCRBY', key, 'count', 1)

-- Severity promotion: replace representative if new alert is more critical
local cur_rank = sev_rank[batch_severity] or 0
if new_rank > cur_rank then
    redis.call('HSET', key, 'task_id', task_id, 'severity', severity)
    batch_task_id = task_id
end

return {1, batch_task_id, new_count}
`

// computeBatchKey creates a grouping key from task_type and source_ip.
func computeBatchKey(taskType, sourceIP string) string {
	raw := strings.ToLower(strings.TrimSpace(taskType)) + ":" + strings.TrimSpace(sourceIP)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)[:16]
}

// effectiveBatchWindow returns the batch window in seconds, adjusted for severity.
func effectiveBatchWindow(severity string) float64 {
	mult, ok := severityMultiplier[strings.ToLower(severity)]
	if !ok {
		mult = 1.0
	}
	return apiBatchWindowSeconds * mult
}

// checkOrCreateBatch runs the Lua batch script against a single Redis key.
// Returns (absorbed, parentTaskID, error).
func checkOrCreateBatch(ctx context.Context, redisKey, taskID, severity string, window float64) (bool, string, error) {
	nowTS := float64(time.Now().UnixMilli()) / 1000.0
	ttl := int(window) + 30 // Redis key TTL with grace period

	result, err := redisClient.Eval(ctx, batchLuaScript, []string{redisKey},
		taskID, fmt.Sprintf("%.3f", nowTS), fmt.Sprintf("%.3f", window),
		apiBatchMaxSize, ttl, strings.ToLower(severity),
	).Result()

	if err != nil {
		return false, "", err
	}

	// Parse Lua response: [status_code, task_id]
	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) < 2 {
		return false, "", nil
	}

	statusCode, _ := resultSlice[0].(int64)
	batchParentID, _ := resultSlice[1].(string)

	if statusCode == 1 {
		return true, batchParentID, nil
	}
	return false, "", nil
}

// tryBatchAlert checks if this alert should be absorbed into an existing batch.
// Returns (shouldSkip, batchParentTaskID).
// shouldSkip=true means another workflow already covers this alert — don't create a new one.
// Checks both source IP (outbound attacks) and destination IP (inbound attacks).
// Fail-open: returns (false, "") if Redis is unavailable.
func tryBatchAlert(ctx context.Context, taskType, sourceIP, destIP, severity, taskID string) (bool, string) {
	if !apiBatchEnabled || redisClient == nil {
		return false, ""
	}

	window := effectiveBatchWindow(severity)

	// Check source IP batch key (catches outbound attacks)
	srcKey := "apibatch:src:" + computeBatchKey(taskType, sourceIP)
	absorbed, parentID, err := checkOrCreateBatch(ctx, srcKey, taskID, severity, window)
	if err != nil {
		log.Printf("[BATCH] Redis batch check failed (src): %v", err)
		return false, ""
	}
	if absorbed {
		log.Printf("[BATCH] Alert absorbed (src): type=%s src_ip=%s batch_parent=%s", taskType, sourceIP, parentID)
		return true, parentID
	}

	// Check destination IP batch key (catches inbound attacks)
	if destIP != "" {
		dstKey := "apibatch:dst:" + computeBatchKey(taskType, destIP)
		absorbed, parentID, err = checkOrCreateBatch(ctx, dstKey, taskID, severity, window)
		if err != nil {
			log.Printf("[BATCH] Redis batch check failed (dst): %v", err)
			return false, ""
		}
		if absorbed {
			log.Printf("[BATCH] Alert absorbed (dst): type=%s dest_ip=%s batch_parent=%s", taskType, destIP, parentID)
			return true, parentID
		}
	}

	return false, ""
}
