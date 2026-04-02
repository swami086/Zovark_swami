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

// Lua script for atomic batch check-and-increment.
// Returns 0 if this is the first alert (proceed with workflow).
// Returns 1 if absorbed into existing batch (skip workflow).
// Returns 2 if batch is full or window expired (proceed with new workflow).
const batchLuaScript = `
local key = KEYS[1]
local task_id = ARGV[1]
local now_ts = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local max_size = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local exists = redis.call('EXISTS', key)
if exists == 0 then
    -- First alert: start new batch
    redis.call('HSET', key, 'task_id', task_id, 'count', 1, 'first_ts', tostring(now_ts))
    redis.call('EXPIRE', key, ttl)
    return {0, task_id}
end

-- Batch exists: check window and size
local first_ts = tonumber(redis.call('HGET', key, 'first_ts'))
local count = tonumber(redis.call('HGET', key, 'count'))
local batch_task_id = redis.call('HGET', key, 'task_id')

if (now_ts - first_ts) > window or count >= max_size then
    -- Window expired or batch full: start new batch
    redis.call('DEL', key)
    redis.call('HSET', key, 'task_id', task_id, 'count', 1, 'first_ts', tostring(now_ts))
    redis.call('EXPIRE', key, ttl)
    return {2, task_id}
end

-- Within window and under max: absorb this alert
redis.call('HINCRBY', key, 'count', 1)
return {1, batch_task_id}
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

// tryBatchAlert checks if this alert should be absorbed into an existing batch.
// Returns (shouldSkip, batchParentTaskID).
// shouldSkip=true means another workflow already covers this alert — don't create a new one.
// Fail-open: returns (false, "") if Redis is unavailable.
func tryBatchAlert(ctx context.Context, taskType, sourceIP, severity, taskID string) (bool, string) {
	if !apiBatchEnabled || redisClient == nil {
		return false, ""
	}

	batchKey := computeBatchKey(taskType, sourceIP)
	redisKey := "apibatch:" + batchKey
	window := effectiveBatchWindow(severity)
	nowTS := float64(time.Now().UnixMilli()) / 1000.0
	ttl := int(window) + 30 // Redis key TTL with grace period

	result, err := redisClient.Eval(ctx, batchLuaScript, []string{redisKey},
		taskID, fmt.Sprintf("%.3f", nowTS), fmt.Sprintf("%.3f", window),
		apiBatchMaxSize, ttl,
	).Result()

	if err != nil {
		// Redis error — fail-open, proceed with workflow
		log.Printf("[BATCH] Redis batch check failed: %v", err)
		return false, ""
	}

	// Parse Lua response: [status_code, task_id]
	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) < 2 {
		return false, ""
	}

	statusCode, _ := resultSlice[0].(int64)
	batchParentID, _ := resultSlice[1].(string)

	switch statusCode {
	case 0:
		// First alert in batch — proceed with workflow
		return false, ""
	case 1:
		// Absorbed into existing batch — skip workflow
		log.Printf("[BATCH] Alert absorbed: type=%s ip=%s batch_parent=%s", taskType, sourceIP, batchParentID)
		return true, batchParentID
	case 2:
		// Window expired or batch full — new batch, proceed with workflow
		return false, ""
	default:
		return false, ""
	}
}
