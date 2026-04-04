package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func dedupHealthCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "dedup",
		Short: "Dedup system health and statistics",
	}
	health := &cobra.Command{
		Use:   "health",
		Short: "Dedup decision distribution, efficiency, top rules",
		Run:   runDedupHealth,
	}
	health.Flags().Bool("json", false, "Output as JSON")
	parent.AddCommand(health)
	return parent
}

func runDedupHealth(cmd *cobra.Command, args []string) {
	jsonOut, _ := cmd.Flags().GetBool("json")

	// Redis counters
	newAlerts := redisInt("dedup:stats:new_alert")
	deduped := redisInt("dedup:stats:deduplicated")
	escalated := redisInt("dedup:stats:severity_escalation")
	retried := redisInt("dedup:stats:retry_after_failure")

	total := newAlerts + deduped + escalated + retried
	ratio := 0.0
	if total > 0 {
		ratio = 100.0 * float64(deduped) / float64(total)
	}

	// Active dedup entries
	dedupCountStr, _ := redisCmd("EVAL",
		"return #redis.call('KEYS','dedup:exact:*')", "0")
	activeDedups := safeInt(dedupCountStr)

	// Batch entries
	srcBatchStr, _ := redisCmd("EVAL",
		"return #redis.call('KEYS','apibatch:src:*')", "0")
	dstBatchStr, _ := redisCmd("EVAL",
		"return #redis.call('KEYS','apibatch:dst:*')", "0")
	srcBatches := safeInt(srcBatchStr)
	dstBatches := safeInt(dstBatchStr)

	// Top deduped task types from DB
	topDeduped, _ := psql(`
		SELECT task_type, SUM(COALESCE(dedup_count,0)) as total_deduped,
			   COUNT(*) as investigations,
			   ROUND(SUM(COALESCE(dedup_count,0))::numeric / GREATEST(COUNT(*),1), 1)
		FROM agent_tasks
		WHERE COALESCE(dedup_count,0) > 0
		  AND created_at > NOW() - INTERVAL '24 hours'
		GROUP BY task_type ORDER BY 2 DESC LIMIT 10`)

	// Backpressure
	bpStr, _ := redisCmd("ZCARD", "zovark:pending_workflows")
	bpDepth := safeInt(bpStr)

	if jsonOut {
		printJSON(map[string]interface{}{
			"decisions": map[string]int{
				"new_alert":           newAlerts,
				"deduplicated":        deduped,
				"severity_escalation": escalated,
				"retry_after_failure": retried,
				"total":               total,
			},
			"dedup_ratio_pct":     ratio,
			"active_dedup_entries": activeDedups,
			"active_batches":      map[string]int{"src": srcBatches, "dst": dstBatches},
			"backpressure_depth":  bpDepth,
			"top_deduped_rules":   topDeduped,
		})
		return
	}

	fmt.Println("DEDUP SYSTEM HEALTH")
	fmt.Println("════════════════════════════════════════════════════════════")

	// Decision distribution
	fmt.Println("  DECISION DISTRIBUTION (last hour):")
	decisions := []struct {
		label string
		count int
	}{
		{"New alerts (investigated)", newAlerts},
		{"Deduplicated (suppressed)", deduped},
		{"Severity escalation (bypass)", escalated},
		{"Retry after failure", retried},
	}
	for _, d := range decisions {
		pct := 0.0
		if total > 0 {
			pct = 100.0 * float64(d.count) / float64(total)
		}
		fmt.Printf("    %-35s %5d  %s %4.1f%%\n", d.label, d.count, bar(pct, 20), pct)
	}
	fmt.Printf("    %-35s %5d\n", "Total", total)

	// Efficiency rating
	fmt.Println()
	if ratio > 95 {
		fmt.Printf("  Efficiency: %s%.1f%%%s — ", colorRed, ratio, colorReset)
		fmt.Println("SIEM issue, not Zovark. Your SIEM rules are firing too frequently.")
		fmt.Println("    → Tune the SIEM rule to fire once per incident, not once per log line.")
		fmt.Println("    → Or increase the dedup TTL if the rule legitimately fires often.")
	} else if ratio > 80 {
		fmt.Printf("  Efficiency: %s%.1f%%%s — Good. Dedup is saving significant pipeline capacity.\n",
			colorGreen, ratio, colorReset)
	} else if ratio > 50 {
		fmt.Printf("  Efficiency: %s%.1f%%%s — Moderate. Most alerts are unique.\n",
			colorYellow, ratio, colorReset)
	} else if total > 0 {
		fmt.Printf("  Efficiency: %.1f%% — Low dedup rate. Alerts are mostly unique.\n", ratio)
	} else {
		fmt.Println("  Efficiency: No data (no alerts in the last hour)")
	}

	// Active entries
	fmt.Printf("\n  Active dedup entries: %d\n", activeDedups)
	fmt.Printf("  Active batch buffers: %d src + %d dst\n", srcBatches, dstBatches)
	fmt.Printf("  Backpressure depth:   %d", bpDepth)
	if bpDepth > 200 {
		fmt.Printf(" %s(ABOVE SOFT LIMIT)%s", colorRed, colorReset)
	}
	fmt.Println()

	// Top deduped rules
	if len(topDeduped) > 0 {
		fmt.Println("\n  TOP DEDUPED RULES (24h):")
		fmt.Printf("    %-28s %8s %8s %8s\n", "Task Type", "Deduped", "Invstg", "Ratio")
		fmt.Println("    " + strings.Repeat("─", 60))
		for _, r := range topDeduped {
			if len(r) < 4 {
				continue
			}
			rat := safeFloat(r[3])
			color := colorReset
			if rat > 100 {
				color = colorYellow
			}
			fmt.Printf("    %-28s %8s %8s %s%8s%s\n", r[0], r[1], r[2], color, r[3], colorReset)
		}
	}

	// Escalation log
	if escalated > 0 {
		fmt.Printf("\n  %d severity escalation(s) in the last hour — critical alerts bypassed dedup correctly.\n", escalated)
	}

	fmt.Println("════════════════════════════════════════════════════════════")
}
