package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"
)

// startOOBServer launches a plain net/http server on :9091 for out-of-band
// diagnostics. It is intentionally outside the Gin router so it stays
// reachable even when the main API is saturated or deadlocked.
func startOOBServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/state", oobStateHandler)

	srv := &http.Server{
		Addr:         ":9091",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("OOB watchdog listening on :9091")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[WARN] OOB server exited: %v", err)
	}
}

// oobStateHandler returns a comprehensive health snapshot as JSON.
// Each dependency check runs concurrently with a 3-second timeout and
// fails independently — a dead Redis does not block the Postgres result.
func oobStateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	gpuTier := getEnvOrDefault("ZOVARK_GPU_TIER", "dev")
	temporalAddr := getEnvOrDefault("TEMPORAL_ADDRESS", "temporal:7233")
	endpointFast := getEnvOrDefault("ZOVARK_LLM_ENDPOINT_FAST",
		getEnvOrDefault("ZOVARK_LLM_ENDPOINT", "http://host.docker.internal:11434/v1/chat/completions"))
	endpointCode := getEnvOrDefault("ZOVARK_LLM_ENDPOINT_CODE",
		getEnvOrDefault("ZOVARK_LLM_ENDPOINT", "http://host.docker.internal:11434/v1/chat/completions"))

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make(map[string]string)
	)

	record := func(name, status string) {
		mu.Lock()
		results[name] = status
		mu.Unlock()
	}

	// --- Postgres check ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		if dbPool == nil {
			record("postgres", "down")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		start := time.Now()
		err := dbPool.Ping(ctx)
		elapsed := time.Since(start)
		if err != nil {
			record("postgres", "down")
		} else if elapsed > 2*time.Second {
			record("postgres", "degraded")
		} else {
			record("postgres", "ok")
		}
	}()

	// --- Redis check ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		if redisClient == nil {
			record("redis", "down")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		start := time.Now()
		err := redisClient.Ping(ctx).Err()
		elapsed := time.Since(start)
		if err != nil {
			record("redis", "down")
		} else if elapsed > 2*time.Second {
			record("redis", "degraded")
		} else {
			record("redis", "ok")
		}
	}()

	// --- Temporal check (TCP dial) ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		conn, err := net.DialTimeout("tcp", temporalAddr, 3*time.Second)
		elapsed := time.Since(start)
		if err != nil {
			record("temporal", "down")
			return
		}
		conn.Close()
		if elapsed > 2*time.Second {
			record("temporal", "degraded")
		} else {
			record("temporal", "ok")
		}
	}()

	// --- Inference checks ---
	// Derive health URL by replacing /v1/chat/completions with /health
	inferenceHealthURL := func(endpoint string) string {
		return strings.Replace(endpoint, "/v1/chat/completions", "/health", 1)
	}

	// Determine if fast and code share the same host:port
	sameHost := inferenceHostPort(endpointFast) == inferenceHostPort(endpointCode)

	checkInference := func(name, endpoint string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			healthURL := inferenceHealthURL(endpoint)
			client := &http.Client{Timeout: 3 * time.Second}
			start := time.Now()
			resp, err := client.Get(healthURL)
			elapsed := time.Since(start)
			if err != nil {
				record(name, "down")
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				record(name, "down")
			} else if elapsed > 2*time.Second {
				record(name, "degraded")
			} else {
				record(name, "ok")
			}
		}()
	}

	if sameHost {
		checkInference("inference", endpointFast)
	} else {
		checkInference("inference_fast", endpointFast)
		checkInference("inference_code", endpointCode)
	}

	wg.Wait()

	// --- Runtime metrics ---
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// --- Build response ---
	response := map[string]interface{}{
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"api":            "ok",
		"postgres":       results["postgres"],
		"redis":          results["redis"],
		"temporal":       results["temporal"],
		"version":        "3.1.0",
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"goroutines":     runtime.NumGoroutine(),
		"heap_mb":        memStats.HeapAlloc / 1024 / 1024,
		"gpu_tier":       gpuTier,
	}

	// Add inference fields based on whether endpoints share the same host
	if sameHost {
		response["inference"] = results["inference"]
	} else {
		response["inference_fast"] = results["inference_fast"]
		response["inference_code"] = results["inference_code"]
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(response)
}

// inferenceHostPort extracts host:port from an LLM endpoint URL.
// Returns the raw string on parse failure so comparison still works.
func inferenceHostPort(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return fmt.Sprintf("%s:%s", host, port)
}
