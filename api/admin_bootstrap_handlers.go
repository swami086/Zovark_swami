package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ============================================================
// BOOTSTRAP WIZARD HANDLERS — First-run synthetic alert injection
// Seeds 3 hardcoded investigation alerts so operators can verify
// the pipeline works end-to-end after deployment.
// ============================================================

// syntheticAlert defines a pre-built alert for bootstrap injection.
type syntheticAlert struct {
	TaskType string
	Prompt   string
	Source   string
	Input    map[string]interface{}
}

// getSyntheticAlerts returns the 3 hardcoded bootstrap alerts.
func getSyntheticAlerts() []syntheticAlert {
	return []syntheticAlert{
		{
			TaskType: "brute_force",
			Prompt:   "Investigate SSH brute force attack from 185.220.101.45 targeting root account",
			Source:   "bootstrap",
			Input: map[string]interface{}{
				"severity": "high",
				"siem_event": map[string]interface{}{
					"title":      "SSH Brute Force - 500 Failed Attempts",
					"source_ip":  "185.220.101.45",
					"username":   "root",
					"rule_name":  "BruteForce",
					"raw_log":    "500 failed password attempts for root from 185.220.101.45 port 22 ssh2. Timestamps span 5 minutes. All attempts use password authentication.",
					"event_count": 500,
				},
			},
		},
		{
			TaskType: "ransomware_triage",
			Prompt:   "Investigate ransomware indicators - shadow copy deletion and mass file encryption",
			Source:   "bootstrap",
			Input: map[string]interface{}{
				"severity": "critical",
				"siem_event": map[string]interface{}{
					"title":     "Ransomware Activity Detected",
					"source_ip": "10.0.1.55",
					"username":  "DOMAIN\\svc-backup",
					"rule_name": "Ransomware",
					"raw_log":   "vssadmin delete shadows /all /quiet && cmd.exe /c wmic shadowcopy delete. Process: conhost.exe spawned by svc-backup. 2847 files renamed to .encrypted extension in C:\\Shares\\Finance within 120 seconds.",
					"host":      "FILE-SVR-01",
				},
			},
		},
		{
			TaskType: "network_beaconing",
			Prompt:   "Investigate C2 beacon activity to known malicious IP 185.100.87.202",
			Source:   "bootstrap",
			Input: map[string]interface{}{
				"severity": "high",
				"siem_event": map[string]interface{}{
					"title":          "C2 Beacon Detected",
					"source_ip":      "10.0.2.100",
					"destination_ip": "185.100.87.202",
					"username":       "jsmith",
					"rule_name":      "C2Beacon",
					"raw_log":        "Periodic HTTPS connections to 185.100.87.202:443 every 60 seconds from 10.0.2.100. JA3 hash: abc123def456. User-Agent: Mozilla/5.0 (compatible). DNS query for update.microsoftonline.evil.com resolved to 185.100.87.202. 47 connections in last hour.",
					"host":           "WS-JSMITH-01",
				},
			},
		},
	}
}

// handleInjectSynthetic creates 3 synthetic investigation alerts.
// POST /api/v1/admin/bootstrap/inject-synthetic
func handleInjectSynthetic(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)
	userID := c.GetString("user_id")
	ctx := c.Request.Context()
	forceParam := c.Query("force")

	// Check if already injected (unless ?force=true)
	if forceParam != "true" {
		var alreadyInjected string
		err := dbPool.QueryRow(ctx,
			`SELECT config_value FROM system_configs
			 WHERE tenant_id = $1 AND config_key = 'bootstrap.synthetic_injected'`,
			tenantID,
		).Scan(&alreadyInjected)
		if err == nil && alreadyInjected == "true" {
			c.JSON(http.StatusConflict, gin.H{
				"error":  "synthetic alerts already injected",
				"detail": "Use ?force=true to inject again",
			})
			return
		}
	}

	alerts := getSyntheticAlerts()
	var taskIDs []string
	var errors []string

	for i, alert := range alerts {
		se, _ := alert.Input["siem_event"].(map[string]interface{})
		flat := map[string]interface{}{}
		for k, v := range se {
			flat[k] = v
		}
		if s, ok := alert.Input["severity"]; ok {
			flat["severity"] = s
		}
		ocsf := NormalizeFlatSIEMToOCSF(flat)
		envelope := map[string]interface{}{}
		for k, v := range alert.Input {
			if k == "siem_event" {
				continue
			}
			envelope[k] = v
		}
		if se != nil {
			if v, ok := se["source_ip"].(string); ok {
				envelope["source_ip"] = v
			}
			if v, ok := se["destination_ip"].(string); ok {
				envelope["dest_ip"] = v
			}
			if v, ok := se["dest_ip"].(string); ok && envelope["dest_ip"] == nil {
				envelope["dest_ip"] = v
			}
			if v, ok := se["username"].(string); ok {
				envelope["user"] = v
			}
			envelope["siem_vendor"] = "bootstrap"
		}
		rawSynthetic, _ := json.Marshal(alert.Input)
		taskID, _, err := createIngestTask(ctx, tenantID, alert.TaskType, alert.Prompt, alert.Source, rawSynthetic, ocsf, envelope)
		if err != nil {
			log.Printf("[BOOTSTRAP] Failed to inject synthetic alert %d (%s): %v", i+1, alert.TaskType, err)
			errors = append(errors, fmt.Sprintf("%s: %v", alert.TaskType, err))
			continue
		}
		taskIDs = append(taskIDs, taskID)
		log.Printf("[BOOTSTRAP] Injected synthetic alert %d: %s -> task %s", i+1, alert.TaskType, taskID)
	}

	if len(taskIDs) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "all synthetic alert injections failed",
			"errors": errors,
		})
		return
	}

	// Mark as injected in system_configs
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		// Non-fatal — alerts were already created
		log.Printf("[BOOTSTRAP] Failed to mark injection complete: %v", err)
	} else {
		_, _ = tx.Exec(ctx,
			`INSERT INTO system_configs (tenant_id, config_key, config_value, description, updated_by)
			 VALUES ($1, 'bootstrap.synthetic_injected', 'true', 'Set by bootstrap inject-synthetic endpoint', $2)
			 ON CONFLICT (tenant_id, config_key) DO UPDATE SET config_value = 'true', updated_by = $2`,
			tenantID, userID,
		)
		_ = tx.Commit(ctx)
	}

	response := gin.H{
		"task_ids": taskIDs,
		"injected": len(taskIDs),
		"total":    len(alerts),
	}
	if len(errors) > 0 {
		response["errors"] = errors
	}

	c.JSON(http.StatusOK, response)
}
