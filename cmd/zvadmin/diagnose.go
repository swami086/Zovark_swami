package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func diagnoseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Run 8 health checks with operator-actionable findings",
		Long: `Checks: service health, pipeline throughput, dedup health, model health,
database health, queue health, container health, disk resources.

Exit codes: 0=ok, 1=warnings, 2=critical`,
		Run: runDiagnose,
	}
	cmd.Flags().Bool("json", false, "Output as JSON")
	return cmd
}

type finding struct {
	Check    string `json:"check"`
	Status   string `json:"status"` // ok, warn, crit
	Detail   string `json:"detail"`
	Action   string `json:"action,omitempty"`
	Category string `json:"category"`
}

func runDiagnose(cmd *cobra.Command, args []string) {
	jsonOut, _ := cmd.Flags().GetBool("json")
	var findings []finding
	worst := 0 // 0=ok, 1=warn, 2=crit

	add := func(f finding) {
		findings = append(findings, f)
		switch f.Status {
		case "crit":
			if worst < 2 {
				worst = 2
			}
		case "warn":
			if worst < 1 {
				worst = 1
			}
		}
	}

	if !jsonOut {
		fmt.Println("ZOVARK APPLIANCE DIAGNOSTICS")
		fmt.Println("════════════════════════════════════════════════════════════")
	}

	// --- 1. Service Health ---
	state, oobErr := fetchOOBState()
	if oobErr != nil {
		add(finding{"service_health", "crit",
			"Cannot reach OOB watchdog on :9091",
			"docker compose restart api", "services"})
	} else {
		services := map[string]string{"postgres": "", "redis": "", "temporal": ""}
		for _, k := range []string{"inference", "inference_fast", "inference_code"} {
			if v, ok := state[k].(string); ok {
				services[k] = v
			}
		}
		for k, v := range state {
			if _, ok := services[k]; ok {
				if s, ok := v.(string); ok {
					services[k] = s
				}
			}
		}
		for svc, st := range services {
			if st == "" {
				continue
			}
			switch st {
			case "ok":
				add(finding{"service_health", "ok", svc + " is healthy", "", "services"})
			case "degraded":
				add(finding{"service_health", "warn", svc + " is degraded (slow response)",
					"docker compose logs " + svc + " --tail 50", "services"})
			default:
				restart := svc
				if svc == "inference" || svc == "inference_fast" || svc == "inference_code" {
					restart = "worker" // inference runs alongside worker; restart triggers reconnect
				}
				add(finding{"service_health", "crit", svc + " is DOWN (" + st + ")",
					"docker compose restart " + restart, "services"})
			}
		}
	}

	// --- 2. Pipeline Throughput ---
	countStr := psqlSingle(`SELECT COUNT(*) FROM agent_tasks WHERE created_at > NOW() - INTERVAL '1 hour'`)
	completedStr := psqlSingle(`SELECT COUNT(*) FROM agent_tasks WHERE status='completed' AND created_at > NOW() - INTERVAL '1 hour'`)
	errorStr := psqlSingle(`SELECT COUNT(*) FROM agent_tasks WHERE status IN ('error','failed') AND created_at > NOW() - INTERVAL '1 hour'`)
	total := safeInt(countStr)
	completed := safeInt(completedStr)
	errors := safeInt(errorStr)

	if total == 0 {
		add(finding{"pipeline_throughput", "ok", "No alerts in the last hour", "", "pipeline"})
	} else {
		pct := 100.0 * float64(completed) / float64(total)
		errPct := 100.0 * float64(errors) / float64(total)
		if errPct > 20 {
			add(finding{"pipeline_throughput", "crit",
				fmt.Sprintf("%d/%d alerts errored (%.0f%%) in last hour", errors, total, errPct),
				"docker compose logs worker --tail 100 — check for Python exceptions", "pipeline"})
		} else if pct < 80 {
			add(finding{"pipeline_throughput", "warn",
				fmt.Sprintf("Only %.0f%% completion rate (%d/%d) in last hour", pct, completed, total),
				"docker compose logs worker --tail 50 — check for stuck workflows", "pipeline"})
		} else {
			add(finding{"pipeline_throughput", "ok",
				fmt.Sprintf("%d alerts, %.0f%% completed, %.0f%% errors in last hour", total, pct, errPct),
				"", "pipeline"})
		}
	}

	// --- 3. Dedup Health ---
	newAlerts := redisInt("dedup:stats:new_alert")
	deduped := redisInt("dedup:stats:deduplicated")
	dedupTotal := newAlerts + deduped
	if dedupTotal > 0 {
		ratio := 100.0 * float64(deduped) / float64(dedupTotal)
		if ratio > 95 {
			add(finding{"dedup_health", "warn",
				fmt.Sprintf("Dedup ratio %.1f%% — almost all alerts suppressed", ratio),
				"Check SIEM rule frequency — likely misfiring. Not a Zovark issue.", "dedup"})
		} else if ratio > 80 {
			add(finding{"dedup_health", "ok",
				fmt.Sprintf("Dedup ratio %.1f%% (%d new, %d deduped)", ratio, newAlerts, deduped),
				"", "dedup"})
		} else {
			add(finding{"dedup_health", "ok",
				fmt.Sprintf("Dedup ratio %.1f%% — normal", ratio), "", "dedup"})
		}
	} else {
		add(finding{"dedup_health", "ok", "No dedup activity in the last hour", "", "dedup"})
	}

	// --- 4. Model Health ---
	gpu := nvidiaSMI()
	if gpu.Available {
		if gpu.MemUsedMB > int(float64(gpu.MemTotalMB)*0.95) {
			add(finding{"model_health", "crit",
				fmt.Sprintf("GPU VRAM nearly full: %dMB/%dMB used", gpu.MemUsedMB, gpu.MemTotalMB),
				"Reduce model concurrency: set MAX_CONCURRENT_ACTIVITIES=4 in docker-compose.yml and restart worker", "model"})
		} else if gpu.TempC > 85 {
			add(finding{"model_health", "warn",
				fmt.Sprintf("GPU temperature high: %d°C", gpu.TempC),
				"Check GPU fan and airflow. Throttling may occur above 90°C.", "model"})
		} else {
			add(finding{"model_health", "ok",
				fmt.Sprintf("%s — VRAM %dMB/%dMB, %d°C, %d%% utilization",
					gpu.Name, gpu.MemUsedMB, gpu.MemTotalMB, gpu.TempC, gpu.UtilPct),
				"", "model"})
		}
	} else {
		// Check inference without GPU
		if state != nil {
			inf, _ := state["inference"].(string)
			if inf == "ok" || inf == "" {
				add(finding{"model_health", "ok",
					"nvidia-smi not available (inference may be using CPU)", "", "model"})
			} else {
				add(finding{"model_health", "crit",
					"Inference down and no GPU detected",
					"Check LLM service: docker compose logs worker --tail 30. Verify ZOVARK_LLM_ENDPOINT is reachable.", "model"})
			}
		}
	}
	// KV cache pressure from OOB inference_metrics
	if state != nil {
		if im, ok := state["inference_metrics"].(map[string]interface{}); ok {
			if avail, _ := im["available"].(bool); avail {
				if kvPct, ok := im["kv_cache_usage_pct"].(float64); ok {
					if kvPct > 90 {
						add(finding{"model_health", "crit",
							fmt.Sprintf("KV cache at %.0f%% — OOM imminent", kvPct),
							"Reduce --ctx-size or --parallel in docker-compose inference config", "model"})
					} else if kvPct > 80 {
						add(finding{"model_health", "warn",
							fmt.Sprintf("KV cache at %.0f%% — monitor under load", kvPct),
							"", "model"})
					}
				}
			}
		}
	}

	// --- 5. Database Health ---
	dbSize := psqlSingle(`SELECT pg_size_pretty(pg_database_size('zovark'))`)
	taskCount := psqlSingle(`SELECT COUNT(*) FROM agent_tasks`)
	connCount := psqlSingle(`SELECT COUNT(*) FROM pg_stat_activity WHERE datname='zovark'`)
	connMax := psqlSingle(`SELECT setting FROM pg_settings WHERE name='max_connections'`)

	cInt := safeInt(connCount)
	mInt := safeInt(connMax)
	if mInt > 0 && float64(cInt)/float64(mInt) > 0.8 {
		add(finding{"database_health", "warn",
			fmt.Sprintf("DB connections %d/%d (%.0f%% capacity)", cInt, mInt, 100.0*float64(cInt)/float64(mInt)),
			"Check for connection leaks: docker compose exec postgres psql -U zovark -c \"SELECT * FROM pg_stat_activity\"", "database"})
	} else {
		add(finding{"database_health", "ok",
			fmt.Sprintf("DB size: %s, tasks: %s, connections: %s/%s",
				dbSize, taskCount, connCount, connMax),
			"", "database"})
	}

	// --- 6. Queue Health ---
	bpDepth, _ := redisCmd("ZCARD", "zovark:pending_workflows")
	depth := safeInt(bpDepth)
	if depth > 200 {
		add(finding{"queue_health", "crit",
			fmt.Sprintf("Backpressure queue depth: %d (soft limit 200)", depth),
			"Workflows accumulating. Increase workers or wait for drain: docker compose logs worker --tail 20", "queue"})
	} else if depth > 50 {
		add(finding{"queue_health", "warn",
			fmt.Sprintf("Backpressure queue depth: %d — elevated", depth),
			"Monitor: docker compose exec redis valkey-cli -a <pw> ZCARD zovark:pending_workflows", "queue"})
	} else {
		add(finding{"queue_health", "ok",
			fmt.Sprintf("Backpressure queue depth: %d", depth), "", "queue"})
	}

	// --- 7. Container Health ---
	containers, cErr := dockerContainers()
	if cErr != nil {
		add(finding{"container_health", "warn", "Cannot list containers: " + cErr.Error(),
			"docker compose ps", "containers"})
	} else {
		unhealthy := 0
		for _, c := range containers {
			if c.State != "running" {
				unhealthy++
				add(finding{"container_health", "crit",
					fmt.Sprintf("Container %s is %s", c.Name, c.State),
					fmt.Sprintf("docker compose restart %s && docker compose logs %s --tail 30",
						c.Name, c.Name), "containers"})
			}
		}
		if unhealthy == 0 {
			add(finding{"container_health", "ok",
				fmt.Sprintf("All %d containers running", len(containers)), "", "containers"})
		}
	}

	// --- 8. Disk Resources ---
	pgDataSize := psqlSingle(`SELECT pg_size_pretty(pg_tablespace_size('pg_default'))`)
	walSize := psqlSingle(`SELECT pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0'))`)
	add(finding{"disk_resources", "ok",
		fmt.Sprintf("PG tablespace: %s, WAL position: %s", pgDataSize, walSize),
		"", "disk"})

	// --- Output ---
	if jsonOut {
		printJSON(map[string]interface{}{
			"status":   []string{"ok", "warnings", "critical"}[worst],
			"findings": findings,
		})
	} else {
		for _, f := range findings {
			switch f.Status {
			case "ok":
				fmt.Println("  " + ok(f.Detail))
			case "warn":
				fmt.Println("  " + warn(f.Detail))
				if f.Action != "" {
					fmt.Println("    → " + f.Action)
				}
			case "crit":
				fmt.Println("  " + crit(f.Detail))
				if f.Action != "" {
					fmt.Println("    → " + f.Action)
				}
			}
		}
		fmt.Println("════════════════════════════════════════════════════════════")
		switch worst {
		case 0:
			fmt.Println(colorize("ALL CHECKS PASSED", colorGreen))
		case 1:
			critCount := 0
			warnCount := 0
			for _, f := range findings {
				if f.Status == "warn" {
					warnCount++
				}
				if f.Status == "crit" {
					critCount++
				}
			}
			_ = critCount
			fmt.Printf("%s (%d warnings)\n", colorize("WARNINGS FOUND", colorYellow), warnCount)
		case 2:
			cc := 0
			for _, f := range findings {
				if f.Status == "crit" {
					cc++
				}
			}
			fmt.Printf("%s (%d critical)\n", colorize("CRITICAL ISSUES", colorRed), cc)
		}
	}

	os.Exit(worst)
}

