package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func alertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Pipeline statistics: verdicts, throughput, risk scores",
		Run:   runAlerts,
	}
	cmd.Flags().Int("hours", 1, "Lookback window in hours")
	cmd.Flags().String("type", "", "Filter by task_type")
	cmd.Flags().Bool("json", false, "Output as JSON")
	return cmd
}

func runAlerts(cmd *cobra.Command, args []string) {
	hours, _ := cmd.Flags().GetInt("hours")
	typeFilter, _ := cmd.Flags().GetString("type")
	jsonOut, _ := cmd.Flags().GetBool("json")

	typeWhere := ""
	if typeFilter != "" {
		typeWhere = fmt.Sprintf(" AND task_type = '%s'", typeFilter)
	}

	// Counts
	totalStr := psqlSingle(fmt.Sprintf(
		`SELECT COUNT(*) FROM agent_tasks WHERE created_at > NOW() - INTERVAL '%d hours'%s`, hours, typeWhere))
	completedStr := psqlSingle(fmt.Sprintf(
		`SELECT COUNT(*) FROM agent_tasks WHERE status='completed' AND created_at > NOW() - INTERVAL '%d hours'%s`, hours, typeWhere))
	dedupedStr := psqlSingle(fmt.Sprintf(
		`SELECT SUM(COALESCE(dedup_count,0)) FROM agent_tasks WHERE created_at > NOW() - INTERVAL '%d hours'%s`, hours, typeWhere))

	total := safeInt(totalStr)
	completed := safeInt(completedStr)
	suppressed := safeInt(dedupedStr)

	// Verdict breakdown
	verdicts, _ := psql(fmt.Sprintf(`
		SELECT output->>'verdict', COUNT(*)
		FROM agent_tasks WHERE status='completed' AND output->>'verdict' IS NOT NULL
		  AND created_at > NOW() - INTERVAL '%d hours'%s
		GROUP BY output->>'verdict' ORDER BY 2 DESC`, hours, typeWhere))

	// Top attack types
	topTypes, _ := psql(fmt.Sprintf(`
		SELECT task_type, COUNT(*),
			   ROUND(AVG((output->>'risk_score')::numeric),0),
			   COUNT(*) FILTER (WHERE output->>'verdict' IN ('true_positive','suspicious'))
		FROM agent_tasks WHERE status='completed' AND output->>'risk_score' IS NOT NULL
		  AND created_at > NOW() - INTERVAL '%d hours'%s
		GROUP BY task_type ORDER BY 2 DESC LIMIT 15`, hours, typeWhere))

	// Low confidence
	lowConf, _ := psql(fmt.Sprintf(`
		SELECT id, task_type, (output->>'risk_score')::int, output->>'verdict'
		FROM agent_tasks WHERE status='completed'
		  AND (output->>'risk_score')::int BETWEEN 1 AND 64
		  AND output->>'verdict' NOT IN ('benign')
		  AND created_at > NOW() - INTERVAL '%d hours'%s
		ORDER BY (output->>'risk_score')::int ASC LIMIT 10`, hours, typeWhere))

	// Latency by path
	latency, _ := psql(fmt.Sprintf(`
		SELECT COALESCE(path_taken,'unknown'), COUNT(*),
			   ROUND(AVG(EXTRACT(EPOCH FROM (completed_at - created_at)))::numeric,1),
			   ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - created_at)))::numeric,1)
		FROM agent_tasks WHERE status='completed' AND completed_at IS NOT NULL
		  AND created_at > NOW() - INTERVAL '%d hours'%s
		GROUP BY path_taken ORDER BY 3 DESC`, hours, typeWhere))

	if jsonOut {
		printJSON(map[string]interface{}{
			"window_hours": hours,
			"received":     total,
			"investigated": completed,
			"suppressed":   suppressed,
			"verdicts":     verdicts,
			"top_types":    topTypes,
			"low_conf":     lowConf,
			"latency":      latency,
		})
		return
	}

	fmt.Printf("PIPELINE STATISTICS (last %d hour%s)\n", hours, plural(hours))
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("  Received:      %d\n", total)
	fmt.Printf("  Investigated:  %d\n", completed)
	fmt.Printf("  Suppressed:    %d (dedup + batch)\n", suppressed)
	fmt.Println()

	// Verdict bar chart
	if len(verdicts) > 0 {
		fmt.Println("  VERDICT BREAKDOWN:")
		maxCount := 0
		for _, r := range verdicts {
			if len(r) >= 2 {
				c := safeInt(r[1])
				if c > maxCount {
					maxCount = c
				}
			}
		}
		for _, r := range verdicts {
			if len(r) < 2 {
				continue
			}
			verdict := r[0]
			count := safeInt(r[1])
			pct := 0.0
			if completed > 0 {
				pct = 100.0 * float64(count) / float64(completed)
			}
			barW := 0
			if maxCount > 0 {
				barW = 30 * count / maxCount
			}
			color := colorGreen
			if strings.Contains(verdict, "true_positive") {
				color = colorRed
			} else if strings.Contains(verdict, "suspicious") || strings.Contains(verdict, "manual") {
				color = colorYellow
			}
			fmt.Printf("    %-22s %s%s%s %4d (%4.1f%%)\n",
				verdict, color, strings.Repeat("█", barW), colorReset, count, pct)
		}
		fmt.Println()
	}

	// Top types
	if len(topTypes) > 0 {
		fmt.Println("  TOP ATTACK TYPES:")
		fmt.Printf("    %-28s %5s %6s %8s\n", "Type", "Count", "Risk", "Detect%")
		for _, r := range topTypes {
			if len(r) < 4 {
				continue
			}
			tt, count, avgRisk, detected := r[0], safeInt(r[1]), safeInt(r[2]), safeInt(r[3])
			detPct := 0.0
			if count > 0 {
				detPct = 100.0 * float64(detected) / float64(count)
			}
			fmt.Printf("    %-28s %5d %6d %7.0f%%\n", tt, count, avgRisk, detPct)
		}
		fmt.Println()
	}

	// Low confidence
	if len(lowConf) > 0 {
		fmt.Println("  LOW-CONFIDENCE ALERTS (risk < 65, non-benign):")
		for _, r := range lowConf {
			if len(r) < 4 {
				continue
			}
			fmt.Printf("    %s  %-25s risk=%-3s verdict=%s\n", r[0][:12], r[1], r[2], r[3])
		}
		fmt.Println()
	}

	// Latency
	if len(latency) > 0 {
		fmt.Println("  LATENCY BY PATH:")
		fmt.Printf("    %-12s %5s %8s %8s\n", "Path", "Count", "Avg(s)", "P95(s)")
		for _, r := range latency {
			if len(r) < 4 {
				continue
			}
			fmt.Printf("    %-12s %5s %8s %8s\n", r[0], r[1], r[2], r[3])
		}
	}

	fmt.Println("════════════════════════════════════════════════════════════")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Ensure import doesn't error
var _ = os.Exit
