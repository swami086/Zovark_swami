// Healthcheck + warmup binary for llama-server inference containers.
// Compiled statically (CGO_ENABLED=0) into the distroless image.
//
// Two-phase health check:
//   1. Wait for /health to return OK (model loaded into VRAM)
//   2. Send a warmup request with the real system prompt prefix
//      → compiles CUDA kernels, populates prefix cache
//      → first real investigation gets a cache hit instead of cold prefill
//
// Exit 0 = healthy + warmed. Exit 1 = unhealthy.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	port := os.Getenv("LLAMA_PORT")
	if port == "" {
		port = "8080"
	}

	// Phase 1: basic /health check
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/health", port))
	if err != nil {
		log.Printf("[healthcheck] /health unreachable: %v", err)
		os.Exit(1)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("[healthcheck] /health returned %d", resp.StatusCode)
		os.Exit(1)
	}

	// Phase 2: warmup (only on first run after container start)
	// Check if warmup marker exists — skip if already warmed
	markerPath := "/tmp/.zovark-warmup-done"
	if _, err := os.Stat(markerPath); err == nil {
		os.Exit(0) // already warmed
	}

	modelAlias := os.Getenv("LLAMA_MODEL_ALIAS")
	if modelAlias == "" {
		modelAlias = "default"
	}

	// Warmup request using the real system prompt prefix from dpo/prompts_v2.py.
	// This populates the KV cache so the first real investigation gets a prefix hit.
	warmupPayload := fmt.Sprintf(`{
		"model": "%s",
		"messages": [
			{"role": "system", "content": "Select investigation tools for this SIEM alert. Output ONLY valid JSON: {\"steps\": [{\"tool\": \"name\", \"args\": {\"arg\": \"value\"}}]}. Rules: Select 3-8 tools. Start with extraction/parsing. Include a scoring or detection tool. End with correlate_with_history and map_mitre."},
			{"role": "user", "content": "warmup: health check passed from monitoring server"}
		],
		"max_tokens": 1,
		"temperature": 0
	}`, modelAlias)

	warmupClient := &http.Client{Timeout: 30 * time.Second}
	warmupResp, err := warmupClient.Post(
		fmt.Sprintf("http://127.0.0.1:%s/v1/chat/completions", port),
		"application/json",
		strings.NewReader(warmupPayload),
	)
	if err != nil {
		log.Printf("[warmup] failed (non-fatal): %v", err)
		// Don't exit 1 — model is loaded, just not warmed
		os.Exit(0)
	}
	defer warmupResp.Body.Close()
	io.Copy(io.Discard, warmupResp.Body)

	if warmupResp.StatusCode == 200 {
		log.Printf("[warmup] model '%s' warmed up, CUDA kernels compiled, prefix cache populated", modelAlias)
		// Write marker so subsequent healthchecks skip warmup
		os.WriteFile(markerPath, []byte("ok"), 0644)
	} else {
		log.Printf("[warmup] returned %d (non-fatal)", warmupResp.StatusCode)
	}

	os.Exit(0)
}
