package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type dnsRequest struct {
	Domain  string `json:"domain"`
	Server  string `json:"server"`
	Type    string `json:"type"`
}

type dnsResponse struct {
	Records    []string `json:"records"`
	DurationMS float64  `json:"duration_ms"`
	Server     string   `json:"server"`
	Type       string   `json:"type"`
	Error      string   `json:"error,omitempty"`
}

func handleDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req dnsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	if !validHostname.MatchString(req.Domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain"})
		return
	}

	qtype := strings.ToUpper(req.Type)
	if qtype == "" {
		qtype = "A"
	}
	if qtype != "A" && qtype != "CNAME" && qtype != "MX" && qtype != "TXT" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "type must be one of: A, CNAME, MX, TXT",
		})
		return
	}

	// Build resolver — custom server if specified
	var resolver *net.Resolver
	serverLabel := "system"

	if req.Server != "" {
		// Ensure server has port
		server := req.Server
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		serverLabel = server
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", server)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	records, err := doLookup(ctx, resolver, req.Domain, qtype)
	duration := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		writeJSON(w, http.StatusOK, dnsResponse{
			Records:    []string{},
			DurationMS: duration,
			Server:     serverLabel,
			Type:       qtype,
			Error:      err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, dnsResponse{
		Records:    records,
		DurationMS: duration,
		Server:     serverLabel,
		Type:       qtype,
	})
}

func doLookup(ctx context.Context, resolver *net.Resolver, domain, qtype string) ([]string, error) {
	switch qtype {
	case "A":
		addrs, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			return nil, err
		}
		return addrs, nil

	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, err
		}
		return []string{cname}, nil

	case "MX":
		mxs, err := resolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("%s (priority %d)", mx.Host, mx.Pref))
		}
		return results, nil

	case "TXT":
		txts, err := resolver.LookupTXT(ctx, domain)
		if err != nil {
			return nil, err
		}
		return txts, nil

	default:
		return nil, fmt.Errorf("unsupported type: %s", qtype)
	}
}
