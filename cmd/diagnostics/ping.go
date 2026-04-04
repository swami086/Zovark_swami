package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var validHostname = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}$`)

type pingRequest struct {
	Host      string `json:"host"`
	TimeoutMS int    `json:"timeout_ms"`
}

type pingResponse struct {
	Success bool    `json:"success"`
	RTTMs   float64 `json:"rtt_ms"`
	Method  string  `json:"method"`
	Host    string  `json:"host"`
	Error   string  `json:"error,omitempty"`
}

// probeICMPAvailable checks at startup whether we can open a raw ICMP socket.
func probeICMPAvailable() bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// handlePing tries ICMP first, then TCP fallback.
func handlePing(icmpAvailable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
			return
		}

		var req pingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}

		if !validHostname.MatchString(req.Host) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hostname"})
			return
		}

		timeout := time.Duration(req.TimeoutMS) * time.Millisecond
		if timeout <= 0 || timeout > 30*time.Second {
			timeout = 3 * time.Second
		}

		if icmpAvailable {
			rtt, err := doPingICMP(req.Host, timeout)
			if err == nil {
				writeJSON(w, http.StatusOK, pingResponse{
					Success: true,
					RTTMs:   rtt,
					Method:  "icmp",
					Host:    req.Host,
				})
				return
			}
			// Fall through to TCP on ICMP failure
		}

		// TCP fallback — try common ports in parallel
		rtt, err := doPingTCPFallback(req.Host, timeout)
		if err != nil {
			writeJSON(w, http.StatusOK, pingResponse{
				Success: false,
				Method:  "tcp_fallback",
				Host:    req.Host,
				Error:   err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, pingResponse{
			Success: true,
			RTTMs:   rtt,
			Method:  "tcp_fallback",
			Host:    req.Host,
		})
	}
}

func doPingICMP(host string, timeout time.Duration) (float64, error) {
	// Resolve hostname to IP
	addrs, err := net.LookupHost(host)
	if err != nil {
		return 0, fmt.Errorf("dns lookup failed: %w", err)
	}
	if len(addrs) == 0 {
		return 0, fmt.Errorf("no addresses for host")
	}
	ip := addrs[0]

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, fmt.Errorf("icmp listen: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0xABCD,
			Seq:  1,
			Data: []byte("ZOVARK-DIAG"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}

	dst := &net.IPAddr{IP: net.ParseIP(ip)}
	start := time.Now()

	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, fmt.Errorf("read: %w", err)
		}
		rtt := float64(time.Since(start).Microseconds()) / 1000.0

		reply, err := icmp.ParseMessage(1, buf[:n]) // protocol 1 = ICMPv4
		if err != nil {
			continue
		}
		if reply.Type == ipv4.ICMPTypeEchoReply {
			return rtt, nil
		}
	}
}

func doPingTCPFallback(host string, timeout time.Duration) (float64, error) {
	ports := []int{5432, 6379, 8080, 443, 80, 22}

	type result struct {
		rtt float64
		err error
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultCh := make(chan result, len(ports))
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", host, p)
			start := time.Now()
			dialer := net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				resultCh <- result{0, err}
				return
			}
			rtt := float64(time.Since(start).Microseconds()) / 1000.0
			conn.Close()
			resultCh <- result{rtt, nil}
		}(port)
	}

	// Close channel when all goroutines finish
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Return first success
	var lastErr error
	for res := range resultCh {
		if res.err == nil {
			cancel() // stop remaining probes
			return res.rtt, nil
		}
		lastErr = res.err
	}
	return 0, fmt.Errorf("all TCP probes failed: %v", lastErr)
}
