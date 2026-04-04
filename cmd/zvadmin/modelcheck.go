package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func modelCheckCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "model",
		Short: "Model calibration and health",
	}
	check := &cobra.Command{
		Use:   "check",
		Short: "Risk score calibration report per attack type",
		Run:   runModelCheck,
	}
	check.Flags().Int("hours", 24, "Lookback window in hours")
	check.Flags().Bool("json", false, "Output as JSON")
	parent.AddCommand(check)
	return parent
}

func runModelCheck(cmd *cobra.Command, args []string) {
	hours, _ := cmd.Flags().GetInt("hours")
	jsonOut, _ := cmd.Flags().GetBool("json")

	// Per-type risk stats
	rows, _ := psql(fmt.Sprintf(`
		SELECT task_type, COUNT(*),
			   ROUND(AVG((output->>'risk_score')::numeric),1),
			   ROUND(COALESCE(STDDEV((output->>'risk_score')::numeric),0),1),
			   MIN((output->>'risk_score')::int),
			   MAX((output->>'risk_score')::int)
		FROM agent_tasks
		WHERE status='completed' AND output->>'risk_score' IS NOT NULL
		  AND created_at > NOW() - INTERVAL '%d hours'
		GROUP BY task_type ORDER BY 3 ASC`, hours))

	// MITRE coverage
	mitre, _ := psql(fmt.Sprintf(`
		SELECT task_type,
			   COUNT(*) FILTER (WHERE output->'mitre_attack' IS NOT NULL
				 AND jsonb_array_length(COALESCE(output->'mitre_attack','[]'::jsonb)) > 0),
			   COUNT(*)
		FROM agent_tasks
		WHERE status='completed' AND output->>'verdict' IN ('true_positive','suspicious')
		  AND created_at > NOW() - INTERVAL '%d hours'
		GROUP BY task_type`, hours))
	mitreMap := map[string]string{}
	for _, r := range mitre {
		if len(r) >= 3 {
			w := safeInt(r[1])
			t := safeInt(r[2])
			pct := 0
			if t > 0 {
				pct = 100 * w / t
			}
			mitreMap[r[0]] = fmt.Sprintf("%d%%", pct)
		}
	}

	// Verdict confidence
	verdictDist, _ := psql(fmt.Sprintf(`
		SELECT output->>'verdict', COUNT(*)
		FROM agent_tasks WHERE status='completed'
		  AND created_at > NOW() - INTERVAL '%d hours'
		GROUP BY output->>'verdict' ORDER BY 2 DESC`, hours))

	benignTypes := map[string]bool{
		"password_change": true, "windows_update": true, "health_check": true,
		"scheduled_backup": true, "user_login": true, "vpn_login": true,
		"benign_system_event": true, "benign-system-event": true,
		"scheduled_task": true, "backup_job": true,
	}

	type typeReport struct {
		Type    string  `json:"type"`
		Count   int     `json:"count"`
		AvgRisk float64 `json:"avg_risk"`
		Stddev  float64 `json:"stddev"`
		Min     int     `json:"min"`
		Max     int     `json:"max"`
		MITRE   string  `json:"mitre_coverage"`
		Flag    string  `json:"flag,omitempty"`
	}

	var reports []typeReport
	var flagged []typeReport

	for _, r := range rows {
		if len(r) < 6 {
			continue
		}
		tr := typeReport{
			Type: r[0], Count: safeInt(r[1]),
			AvgRisk: safeFloat(r[2]), Stddev: safeFloat(r[3]),
			Min: safeInt(r[4]), Max: safeInt(r[5]),
			MITRE: mitreMap[r[0]],
		}
		if tr.MITRE == "" {
			tr.MITRE = "n/a"
		}

		isBenign := benignTypes[tr.Type]
		if !isBenign && tr.Count >= 2 {
			if tr.AvgRisk < 65 {
				tr.Flag = fmt.Sprintf("LOW RISK (avg %.0f < 65)", tr.AvgRisk)
			}
			if tr.Stddev > 15 {
				if tr.Flag != "" {
					tr.Flag += " + "
				}
				tr.Flag += fmt.Sprintf("INCONSISTENT (stddev %.0f > 15)", tr.Stddev)
			}
		}
		if isBenign && tr.AvgRisk > 25 {
			tr.Flag = fmt.Sprintf("BENIGN FP (avg %.0f > 25)", tr.AvgRisk)
		}

		reports = append(reports, tr)
		if tr.Flag != "" {
			flagged = append(flagged, tr)
		}
	}

	if jsonOut {
		printJSON(map[string]interface{}{
			"window_hours":        hours,
			"types":               reports,
			"flagged":             flagged,
			"verdict_distribution": verdictDist,
		})
		return
	}

	fmt.Printf("MODEL CALIBRATION REPORT (last %d hours)\n", hours)
	fmt.Println("════════════════════════════════════════════════════════════")

	// Separation gap
	var attackAvgs, benignAvgs []float64
	for _, r := range reports {
		if benignTypes[r.Type] {
			benignAvgs = append(benignAvgs, r.AvgRisk)
		} else if r.AvgRisk > 0 {
			attackAvgs = append(attackAvgs, r.AvgRisk)
		}
	}
	if len(attackAvgs) > 0 && len(benignAvgs) > 0 {
		minAttack := attackAvgs[0]
		for _, v := range attackAvgs {
			if v < minAttack {
				minAttack = v
			}
		}
		maxBenign := benignAvgs[0]
		for _, v := range benignAvgs {
			if v > maxBenign {
				maxBenign = v
			}
		}
		gap := minAttack - maxBenign
		label := colorize(fmt.Sprintf("%.0f points", gap), colorGreen)
		if gap < 30 {
			label = colorize(fmt.Sprintf("%.0f points — TOO CLOSE", gap), colorRed)
		} else if gap < 50 {
			label = colorize(fmt.Sprintf("%.0f points", gap), colorYellow)
		}
		fmt.Printf("  Attack/Benign separation gap: %s (attack min=%.0f, benign max=%.0f)\n\n", label, minAttack, maxBenign)
	}

	// Per-type table
	fmt.Printf("  %-28s %5s %6s %6s %4s %4s %6s  %s\n",
		"Type", "Count", "Avg", "StdDv", "Min", "Max", "MITRE", "Flag")
	fmt.Println("  " + strings.Repeat("─", 90))
	for _, r := range reports {
		flag := ""
		if r.Flag != "" {
			flag = colorize(r.Flag, colorRed)
		}
		fmt.Printf("  %-28s %5d %6.0f %6.0f %4d %4d %6s  %s\n",
			r.Type, r.Count, r.AvgRisk, r.Stddev, r.Min, r.Max, r.MITRE, flag)
	}

	// Verdict distribution
	if len(verdictDist) > 0 {
		fmt.Printf("\n  VERDICT DISTRIBUTION:\n")
		for _, r := range verdictDist {
			if len(r) >= 2 {
				fmt.Printf("    %-25s %s\n", r[0], r[1])
			}
		}
	}

	// Flagged summary
	if len(flagged) > 0 {
		fmt.Printf("\n  %s %d types need calibration work\n", colorize("FLAGGED:", colorYellow), len(flagged))
	} else {
		fmt.Printf("\n  %s All types within calibration thresholds\n", colorize("CLEAN:", colorGreen))
	}

	fmt.Println("════════════════════════════════════════════════════════════")
}
