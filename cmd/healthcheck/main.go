// Healthcheck binary for distroless containers.
// Compiled statically (CGO_ENABLED=0) so it runs without libc.
// Checks the /ready endpoint and exits 0 (healthy) or 1 (unhealthy).
package main

import (
	"net/http"
	"os"
	"time"
)

func main() {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get("http://127.0.0.1:8090/ready")
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		os.Exit(0)
	}
	os.Exit(1)
}
