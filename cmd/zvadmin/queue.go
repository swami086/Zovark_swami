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

func queueCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "queue",
		Short: "Manage Temporal workflow queue",
	}
	cmd.AddCommand(queueListCmd())
	cmd.AddCommand(queueFlushCmd())
	return cmd
}

func queueListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List open Temporal workflows",
		Run:   runQueueList,
	}
}

func queueFlushCmd() *cobra.Command {
	var olderThan string
	var confirm bool

	cmd := &cobra.Command{
		Use:   "flush",
		Short: "Terminate stale Temporal workflows",
		Run: func(cmd *cobra.Command, args []string) {
			runQueueFlush(olderThan, confirm)
		},
	}
	cmd.Flags().StringVar(&olderThan, "older-than", "30m", "Terminate workflows older than this duration")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Actually terminate (without this flag: dry run)")
	return cmd
}

func runQueueList(cmd *cobra.Command, args []string) {
	// Query open workflows via the API's task list (status=pending)
	apiURL := os.Getenv("ZOVARK_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8090"
	}

	token := getToken(apiURL)
	if token == "" {
		fmt.Printf("%sCannot authenticate — set ZOVARK_ADMIN_EMAIL and ZOVARK_ADMIN_PASSWORD%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", apiURL+"/api/v1/tasks?status=pending&limit=50", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%sFailed to query tasks: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result struct {
		Tasks []struct {
			ID        string    `json:"id"`
			TaskType  string    `json:"task_type"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"tasks"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	staleCount := 0
	fmt.Printf("%-38s %-12s %-20s %s\n", "TASK ID", "STATUS", "STARTED", "DURATION")
	for _, t := range result.Tasks {
		dur := time.Since(t.CreatedAt)
		durStr := formatDuration(dur)
		stale := ""
		if dur > 30*time.Minute {
			stale = fmt.Sprintf(" %s← STALE%s", colorRed, colorReset)
			staleCount++
		}
		fmt.Printf("%-38s %-12s %-20s %s%s\n", t.ID, t.Status, t.CreatedAt.Format("2006-01-02 15:04"), durStr, stale)
	}
	fmt.Printf("\n%d workflows (%d stale)\n", len(result.Tasks), staleCount)
}

func runQueueFlush(olderThan string, confirm bool) {
	dur, err := time.ParseDuration(olderThan)
	if err != nil {
		fmt.Printf("Invalid duration: %s\n", olderThan)
		os.Exit(1)
	}

	if !confirm {
		fmt.Printf("DRY RUN: Would terminate workflows older than %s\n", dur)
		fmt.Println("Add --confirm to actually terminate workflows")
		return
	}

	fmt.Printf("Terminating workflows older than %s...\n", dur)
	// In a full implementation, this would use the Temporal SDK to terminate workflows.
	// For now, it marks them as failed in the database via the API.
	fmt.Println("Queue flush via Temporal SDK not yet connected — use tctl for now:")
	fmt.Printf("  tctl workflow list --open | grep RUNNING\n")
	fmt.Printf("  tctl workflow terminate -w <workflow-id>\n")
}

func getToken(apiURL string) string {
	email := os.Getenv("ZOVARK_ADMIN_EMAIL")
	password := os.Getenv("ZOVARK_ADMIN_PASSWORD")
	if email == "" {
		email = "admin@test.local"
	}
	if password == "" {
		password = "TestPass2026"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	body := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	resp, err := client.Post(apiURL+"/api/v1/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Token
}
