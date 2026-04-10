package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ============================================================
// LAYER 3: TEMPORAL QUEUE DEPTH BACKPRESSURE
//
// Tracks active workflow count and throttles creation when the
// queue is deep. Uses Redis sorted set for distributed tracking.
//
// Soft limit: queue task in DB (status='queued'), return 202
// Hard limit: reject with 503 + Retry-After
//
// Background drain goroutine processes queued tasks.
// Fail-open: if Redis unavailable, create workflow immediately.
// ============================================================

var (
	backpressureEnabled   = true
	maxPendingWorkflows   = 200
	maxPendingHard        = 1000
	backpressureWindowSec = 120 // Track workflows started in last N seconds
)

func init() {
	if v := os.Getenv("ZOVARK_BACKPRESSURE_ENABLED"); v == "false" {
		backpressureEnabled = false
	}
	if v := os.Getenv("ZOVARK_MAX_PENDING_WORKFLOWS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxPendingWorkflows = n
		}
	}
	if v := os.Getenv("ZOVARK_MAX_PENDING_WORKFLOWS_HARD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxPendingHard = n
		}
	}
}

const backpressureKey = "temporal:workflow_starts"

// checkBackpressure returns (allowed, queueDepth).
// allowed=true means a new workflow can be started.
// allowed=false with queueDepth < hard limit means "queue it".
// allowed=false with queueDepth >= hard limit means "reject".
// Fail-open: returns (true, 0) if Redis is unavailable.
func checkBackpressure(ctx context.Context) (bool, int) {
	if !backpressureEnabled || redisClient == nil {
		return true, 0
	}

	now := float64(time.Now().Unix())
	cutoff := now - float64(backpressureWindowSec)

	// Clean old entries and count current
	pipe := redisClient.Pipeline()
	pipe.ZRemRangeByScore(ctx, backpressureKey, "-inf", fmt.Sprintf("%.0f", cutoff))
	countCmd := pipe.ZCard(ctx, backpressureKey)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, 0 // fail-open
	}

	depth := int(countCmd.Val())

	if depth >= maxPendingHard {
		return false, depth
	}
	if depth >= maxPendingWorkflows {
		return false, depth
	}
	return true, depth
}

// isHardLimitReached returns true if queue depth exceeds the hard limit.
func isHardLimitReached(depth int) bool {
	return depth >= maxPendingHard
}

// recordWorkflowStart tracks a newly started workflow for backpressure counting.
func recordWorkflowStart(ctx context.Context, workflowID string) {
	if !backpressureEnabled || redisClient == nil {
		return
	}

	now := float64(time.Now().Unix())
	err := redisClient.ZAdd(ctx, backpressureKey, redis.Z{Score: now, Member: workflowID}).Err()
	if err != nil {
		log.Printf("[BACKPRESSURE] Failed to record workflow start: %v", err)
	}
	// Set expiry on the sorted set to auto-cleanup
	redisClient.Expire(ctx, backpressureKey, time.Duration(backpressureWindowSec+60)*time.Second)
}

// startQueueDrainLoop runs a background goroutine that processes queued tasks.
// It polls agent_tasks WHERE status='queued' and starts workflows for them.
func startQueueDrainLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	log.Println("[BACKPRESSURE] Queue drain goroutine started")

	for {
		select {
		case <-ctx.Done():
			log.Println("[BACKPRESSURE] Queue drain goroutine stopped")
			return
		case <-ticker.C:
			// Compute dynamic drain count based on headroom
			_, depth := checkBackpressure(ctx)
			headroom := maxPendingWorkflows - depth
			if headroom <= 0 {
				continue // At capacity, wait
			}
			drainCount := headroom / 10
			if drainCount < 1 {
				drainCount = 1
			}
			if drainCount > 30 {
				drainCount = 30
			}
			drainQueuedTasks(ctx, drainCount)
		}
	}
}

// drainQueuedTasks processes up to maxDrain queued tasks per tick.
func drainQueuedTasks(ctx context.Context, maxDrain int) {
	if dbPool == nil || tc == nil {
		return
	}

	// Check if we have capacity
	allowed, _ := checkBackpressure(ctx)
	if !allowed {
		return // Still at capacity, wait
	}

	rows, err := dbPool.Query(ctx,
		`SELECT id, tenant_id, task_type, input FROM agent_tasks
		 WHERE status = 'queued'
		 ORDER BY created_at ASC
		 LIMIT $1`, maxDrain)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var taskID, tenantID, taskType string
		var input map[string]interface{}
		if err := rows.Scan(&taskID, &tenantID, &taskType, &input); err != nil {
			continue
		}

		// Re-check backpressure for each task
		allowed, _ := checkBackpressure(ctx)
		if !allowed {
			break
		}

		pubCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := publishTaskNew(pubCtx, tenantID, taskID, taskType, input)
		cancel()
		if err != nil {
			log.Printf("[DRAIN] Failed to publish queued task %s: %v", taskID, err)
			_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'failed' WHERE id = $1", taskID)
			continue
		}

		_, _ = dbPool.Exec(ctx, "UPDATE agent_tasks SET status = 'pending' WHERE id = $1", taskID)
		recordWorkflowStart(ctx, "task-"+taskID)
		log.Printf("[DRAIN] Published queued task %s (type=%s) to Redpanda", taskID, taskType)
	}
}
