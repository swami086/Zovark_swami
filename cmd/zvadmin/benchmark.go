package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func benchmarkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "benchmark",
		Short: "Run model validation benchmark (3 synthetic alerts)",
		Run:   runBenchmark,
	}
}

type benchAlert struct {
	Name           string
	TaskType       string
	Payload        string
	ExpectedVerdict string
	MinRisk        int
}

func runBenchmark(cmd *cobra.Command, args []string) {
	apiURL := os.Getenv("ZOVARK_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8090"
	}

	token := getToken(apiURL)
	if token == "" {
		fmt.Printf("%sCannot authenticate%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	alerts := []benchAlert{
		{
			Name: "Brute Force", TaskType: "brute_force",
			Payload: `{"task_type":"brute_force","input":{"prompt":"SSH brute force benchmark","severity":"high","siem_event":{"title":"SSH BF","source_ip":"185.220.101.45","username":"root","rule_name":"BruteForce","raw_log":"500 failed login attempts for root from 185.220.101.45 in 60 seconds via sshd"}}}`,
			ExpectedVerdict: "true_positive", MinRisk: 70,
		},
		{
			Name: "Ransomware", TaskType: "ransomware",
			Payload: `{"task_type":"ransomware","input":{"prompt":"Ransomware benchmark","severity":"critical","siem_event":{"title":"Ransomware","source_ip":"10.0.0.100","hostname":"VICTIM","rule_name":"Ransomware","raw_log":"vssadmin.exe delete shadows /all /quiet 1500 files renamed to .locked extension README_DECRYPT.txt"}}}`,
			ExpectedVerdict: "true_positive", MinRisk: 80,
		},
		{
			Name: "C2 Beacon", TaskType: "c2",
			Payload: `{"task_type":"c2","input":{"prompt":"C2 beacon benchmark","severity":"critical","siem_event":{"title":"C2 Beacon","source_ip":"10.0.0.200","destination_ip":"185.100.87.202","rule_name":"C2Detection","raw_log":"Regular beacon detected interval=60s to 185.100.87.202:4444 cobalt strike User-Agent beacon"}}}`,
			ExpectedVerdict: "true_positive", MinRisk: 70,
		},
	}

	fmt.Println("ZOVARK MODEL BENCHMARK")
	fmt.Println("──────────────────────")

	client := &http.Client{Timeout: 10 * time.Second}
	allPass := true
	var latencies []time.Duration

	for _, alert := range alerts {
		start := time.Now()

		// Submit alert
		req, _ := http.NewRequest("POST", apiURL+"/api/v1/tasks", strings.NewReader(alert.Payload))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%-18s SUBMIT FAILED: %v\n", alert.Name, err)
			allPass = false
			continue
		}

		var submitResult struct {
			TaskID string `json:"task_id"`
			Status string `json:"status"`
		}
		json.NewDecoder(resp.Body).Decode(&submitResult)
		resp.Body.Close()

		taskID := submitResult.TaskID
		if taskID == "" {
			fmt.Printf("%-18s SUBMIT FAILED: no task_id\n", alert.Name)
			allPass = false
			continue
		}

		// Poll for result
		var verdict string
		var risk float64
		timeout := time.After(120 * time.Second)
		ticker := time.NewTicker(5 * time.Second)
		completed := false

		for !completed {
			select {
			case <-timeout:
				fmt.Printf("%-18s TIMEOUT (120s)\n", alert.Name)
				allPass = false
				completed = true
			case <-ticker.C:
				pollReq, _ := http.NewRequest("GET", apiURL+"/api/v1/tasks/"+taskID, nil)
				pollReq.Header.Set("Authorization", "Bearer "+token)
				pollResp, err := client.Do(pollReq)
				if err != nil {
					continue
				}
				var taskResult map[string]interface{}
				json.NewDecoder(pollResp.Body).Decode(&taskResult)
				pollResp.Body.Close()

				if status, _ := taskResult["status"].(string); status == "completed" {
					dur := time.Since(start)
					latencies = append(latencies, dur)

					output, _ := taskResult["output"].(map[string]interface{})
					verdict, _ = output["verdict"].(string)
					risk, _ = output["risk_score"].(float64)

					pass := verdict == alert.ExpectedVerdict && int(risk) >= alert.MinRisk
					mark := fmt.Sprintf("%s✓ PASS%s", colorGreen, colorReset)
					if !pass {
						mark = fmt.Sprintf("%s✗ FAIL%s", colorRed, colorReset)
						allPass = false
					}
					fmt.Printf("%-18s %-18s %-7.0f ≥%-7d %s\n", alert.Name, verdict, risk, alert.MinRisk, mark)
					completed = true
				}
			}
		}
		ticker.Stop()
	}

	fmt.Println("──────────────────────")
	if allPass {
		fmt.Printf("%sBENCHMARK PASSED — 3/3 alerts correct%s\n", colorGreen, colorReset)
	} else {
		fmt.Printf("%sBENCHMARK FAILED%s\n", colorRed, colorReset)
	}

	if len(latencies) > 0 {
		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		avg := total / time.Duration(len(latencies))
		fmt.Printf("Avg investigation latency: %s\n", avg.Round(time.Millisecond))
	}

	if !allPass {
		os.Exit(1)
	}
}
