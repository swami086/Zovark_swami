// Tiny healthcheck binary for Docker HEALTHCHECK.
// Calls GET http://127.0.0.1:{DIAG_PORT}/health and exits 0 on success.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("DIAG_PORT")
	if port == "" {
		port = "8091"
	}

	token := os.Getenv("DIAG_AUTH_TOKEN")

	url := fmt.Sprintf("http://127.0.0.1:%s/health", port)

	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}

	if token != "" {
		req.Header.Set("X-Diag-Token", token)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "unhealthy: status %d\n", resp.StatusCode)
	os.Exit(1)
}
