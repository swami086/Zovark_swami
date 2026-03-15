package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// INTEGRATION MANAGEMENT — Slack, Teams, etc.
// ============================================================

// POST /api/v1/integrations/slack/test — test Slack webhook connectivity
func testSlackWebhookHandler(c *gin.Context) {
	var req struct {
		WebhookURL string `json:"webhook_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Send a test message
	payload := map[string]interface{}{
		"text": "HYDRA integration test — connection verified.",
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": "*HYDRA Integration Test*\nSlack webhook connectivity verified successfully.",
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(req.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("Failed to connect to Slack webhook: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "Slack webhook test successful",
		})
	} else {
		c.JSON(http.StatusBadGateway, gin.H{
			"status":      "error",
			"http_status": resp.StatusCode,
			"error":       string(respBody),
		})
	}
}

// PUT /api/v1/integrations/slack — configure Slack webhook for tenant
func configureSlackWebhookHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var req struct {
		WebhookURL string   `json:"webhook_url" binding:"required"`
		Events     []string `json:"events"`
		Channel    string   `json:"channel"`
		Enabled    *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Events == nil {
		req.Events = []string{"investigation_complete", "approval_needed", "sla_breach"}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	config := map[string]interface{}{
		"slack_webhook_url": req.WebhookURL,
		"slack_events":      req.Events,
		"slack_channel":     req.Channel,
		"slack_enabled":     enabled,
	}

	configJSON, _ := json.Marshal(config)

	// Upsert into tenant settings
	_, err := dbPool.Exec(c.Request.Context(),
		`UPDATE tenants
		 SET settings = COALESCE(settings, '{}'::jsonb) || $1::jsonb,
		     updated_at = NOW()
		 WHERE id = $2`,
		configJSON, tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "save Slack configuration")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "configured",
		"webhook_url": req.WebhookURL,
		"events":      req.Events,
		"enabled":     enabled,
	})
}

// POST /api/v1/integrations/teams/test — test Teams webhook connectivity
func testTeamsWebhookHandler(c *gin.Context) {
	var req struct {
		WebhookURL string `json:"webhook_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payload := map[string]interface{}{
		"type": "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body": []map[string]interface{}{
						{
							"type":   "TextBlock",
							"text":   "HYDRA Integration Test",
							"weight": "bolder",
							"size":   "large",
						},
						{
							"type": "TextBlock",
							"text": "Microsoft Teams webhook connectivity verified successfully.",
							"wrap": true,
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(req.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("Failed to connect to Teams webhook: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "Teams webhook test successful",
		})
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		c.JSON(http.StatusBadGateway, gin.H{
			"status":      "error",
			"http_status": resp.StatusCode,
			"error":       string(respBody),
		})
	}
}

// PUT /api/v1/integrations/teams — configure Teams webhook for tenant
func configureTeamsWebhookHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	var req struct {
		WebhookURL string   `json:"webhook_url" binding:"required"`
		Events     []string `json:"events"`
		Enabled    *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Events == nil {
		req.Events = []string{"investigation_complete", "approval_needed", "sla_breach"}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	config := map[string]interface{}{
		"teams_webhook_url": req.WebhookURL,
		"teams_events":      req.Events,
		"teams_enabled":     enabled,
	}

	configJSON, _ := json.Marshal(config)

	_, err := dbPool.Exec(c.Request.Context(),
		`UPDATE tenants
		 SET settings = COALESCE(settings, '{}'::jsonb) || $1::jsonb,
		     updated_at = NOW()
		 WHERE id = $2`,
		configJSON, tenantID,
	)
	if err != nil {
		respondInternalError(c, err, "save Teams configuration")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "configured",
		"webhook_url": req.WebhookURL,
		"events":      req.Events,
		"enabled":     enabled,
	})
}
