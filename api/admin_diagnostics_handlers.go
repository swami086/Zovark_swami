package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// DIAGNOSTICS PROXY HANDLERS — Forward requests to diagnostics sidecar
// The sidecar runs network probes that the API container can't do itself
// (different network namespace, custom DNS, raw TCP, etc.).
// ============================================================

var (
	diagnosticsURL   string
	diagAuthToken    string
	diagHTTPClient   *http.Client
)

func init() {
	diagnosticsURL = getEnvOrDefault("DIAGNOSTICS_URL", "http://zovark-diagnostics:8091")
	diagAuthToken = getEnvOrDefault("DIAG_AUTH_TOKEN", "")
	diagHTTPClient = &http.Client{Timeout: 15 * time.Second}
}

// proxyToDiagnostics forwards a request to the diagnostics sidecar and
// streams back the response. It handles both POST (with JSON body) and GET.
func proxyToDiagnostics(c *gin.Context, method, path string) {
	targetURL := fmt.Sprintf("%s%s", diagnosticsURL, path)

	var bodyReader io.Reader
	if method == http.MethodPost {
		bodyReader = c.Request.Body
		defer c.Request.Body.Close()
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), method, targetURL, bodyReader)
	if err != nil {
		respondInternalError(c, err, "create diagnostics proxy request")
		return
	}

	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if diagAuthToken != "" {
		req.Header.Set("X-Diag-Token", diagAuthToken)
	}

	resp, err := diagHTTPClient.Do(req)
	if err != nil {
		log.Printf("[DIAG] Sidecar unreachable at %s: %v", targetURL, err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error":   "diagnostics sidecar unreachable",
			"detail":  err.Error(),
			"sidecar": diagnosticsURL,
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		respondInternalError(c, err, "read diagnostics response")
		return
	}

	// Try to parse as JSON for clean forwarding; fall back to raw string
	var jsonBody interface{}
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		c.JSON(resp.StatusCode, jsonBody)
	} else {
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

// handleDiagPing proxies to POST sidecar:8091/ping
func handleDiagPing(c *gin.Context) {
	proxyToDiagnostics(c, http.MethodPost, "/ping")
}

// handleDiagHTTPCheck proxies to POST sidecar:8091/http-check
func handleDiagHTTPCheck(c *gin.Context) {
	proxyToDiagnostics(c, http.MethodPost, "/http-check")
}

// handleDiagDNS proxies to POST sidecar:8091/dns
func handleDiagDNS(c *gin.Context) {
	proxyToDiagnostics(c, http.MethodPost, "/dns")
}

// handleDiagTCP proxies to POST sidecar:8091/tcp
func handleDiagTCP(c *gin.Context) {
	proxyToDiagnostics(c, http.MethodPost, "/tcp")
}

// handleDiagParseTest proxies to POST sidecar:8091/parse-test
func handleDiagParseTest(c *gin.Context) {
	proxyToDiagnostics(c, http.MethodPost, "/parse-test")
}

// handleDiagHealth proxies to GET sidecar:8091/health
func handleDiagHealth(c *gin.Context) {
	if !enforceAdminDiagnosticRateLimit(c) {
		return
	}
	proxyToDiagnostics(c, http.MethodGet, "/health")
}

// handleSystemHealth combines the OOB watchdog state with the diagnostics
// sidecar health into a single response. Useful for the dashboard to show
// one-glance system status.
func handleSystemHealth(c *gin.Context) {
	if !enforceAdminDiagnosticRateLimit(c) {
		return
	}
	type componentResult struct {
		name string
		data interface{}
		err  error
	}

	results := make(chan componentResult, 2)

	// Fetch OOB state concurrently
	go func() {
		oobURL := fmt.Sprintf("http://127.0.0.1:9091/debug/state")
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(oobURL)
		if err != nil {
			results <- componentResult{name: "oob", err: err}
			return
		}
		defer resp.Body.Close()
		var data interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			results <- componentResult{name: "oob", err: err}
			return
		}
		results <- componentResult{name: "oob", data: data}
	}()

	// Fetch diagnostics health concurrently
	go func() {
		diagURL := fmt.Sprintf("%s/health", diagnosticsURL)
		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, diagURL, nil)
		if err != nil {
			results <- componentResult{name: "diagnostics", err: err}
			return
		}
		if diagAuthToken != "" {
			req.Header.Set("X-Diag-Token", diagAuthToken)
		}
		resp, err := diagHTTPClient.Do(req)
		if err != nil {
			results <- componentResult{name: "diagnostics", err: err}
			return
		}
		defer resp.Body.Close()
		var data interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			results <- componentResult{name: "diagnostics", err: err}
			return
		}
		results <- componentResult{name: "diagnostics", data: data}
	}()

	// Collect results
	response := gin.H{
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"hostname":       os.Getenv("HOSTNAME"),
	}

	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil {
			response[r.name] = gin.H{"status": "unreachable", "error": r.err.Error()}
		} else {
			response[r.name] = r.data
		}
	}

	c.JSON(http.StatusOK, response)
}
