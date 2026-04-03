package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type tcpRequest struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TimeoutMS int    `json:"timeout_ms"`
}

type tcpResponse struct {
	Success   bool    `json:"success"`
	ConnectMS float64 `json:"connect_ms"`
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	Error     string  `json:"error,omitempty"`
}

func handleTCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req tcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if !validHostname.MatchString(req.Host) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hostname"})
		return
	}

	if req.Port <= 0 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "port must be 1-65535"})
		return
	}

	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}

	addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		writeJSON(w, http.StatusOK, tcpResponse{
			Success: false,
			Host:    req.Host,
			Port:    req.Port,
			Error:   err.Error(),
		})
		return
	}
	conn.Close()

	writeJSON(w, http.StatusOK, tcpResponse{
		Success:   true,
		ConnectMS: elapsed,
		Host:      req.Host,
		Port:      req.Port,
	})
}
