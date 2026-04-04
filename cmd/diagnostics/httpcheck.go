package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"time"
)

type httpCheckRequest struct {
	URL        string `json:"url"`
	TimeoutMS  int    `json:"timeout_ms"`
	SkipVerify bool   `json:"skip_verify"`
}

type httpCheckTiming struct {
	DNSMS     float64 `json:"dns_ms"`
	ConnectMS float64 `json:"connect_ms"`
	TLSMS     float64 `json:"tls_ms"`
	TTFBMS    float64 `json:"ttfb_ms"`
	TotalMS   float64 `json:"total_ms"`
}

type httpCheckTLS struct {
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	Expiry         string `json:"expiry"`
	DaysUntilExpiry int   `json:"days_until_expiry"`
	Valid          bool   `json:"valid"`
}

type httpCheckResponse struct {
	Success    bool             `json:"success"`
	StatusCode int              `json:"status_code,omitempty"`
	Timing     *httpCheckTiming `json:"timing,omitempty"`
	TLS        *httpCheckTLS    `json:"tls,omitempty"`
	RemoteIP   string           `json:"remote_ip,omitempty"`
	Error      string           `json:"error,omitempty"`
}

func handleHTTPCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req httpCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}

	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 10 * time.Second
	}

	var (
		dnsStart, dnsEnd         time.Time
		connectStart, connectEnd time.Time
		tlsStart, tlsEnd         time.Time
		gotFirstByte             time.Time
		remoteAddr               string
		peerCerts                []*x509.Certificate
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
		},
		ConnectStart: func(_, _ string) {
			connectStart = time.Now()
		},
		ConnectDone: func(_, addr string, err error) {
			connectEnd = time.Now()
			if err == nil {
				remoteAddr = addr
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			tlsEnd = time.Now()
			peerCerts = state.PeerCertificates
		},
		GotFirstResponseByte: func() {
			gotFirstByte = time.Now()
		},
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: req.SkipVerify,
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Don't follow redirects — report the direct response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpReq, err := http.NewRequest(http.MethodGet, req.URL, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, httpCheckResponse{
			Success: false,
			Error:   fmt.Sprintf("bad url: %v", err),
		})
		return
	}
	httpReq = httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), trace))

	overallStart := time.Now()
	resp, err := client.Do(httpReq)
	overallEnd := time.Now()

	if err != nil {
		writeJSON(w, http.StatusOK, httpCheckResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	timing := &httpCheckTiming{
		TotalMS: msElapsed(overallStart, overallEnd),
	}
	if !dnsStart.IsZero() && !dnsEnd.IsZero() {
		timing.DNSMS = msElapsed(dnsStart, dnsEnd)
	}
	if !connectStart.IsZero() && !connectEnd.IsZero() {
		timing.ConnectMS = msElapsed(connectStart, connectEnd)
	}
	if !tlsStart.IsZero() && !tlsEnd.IsZero() {
		timing.TLSMS = msElapsed(tlsStart, tlsEnd)
	}
	if !gotFirstByte.IsZero() {
		timing.TTFBMS = msElapsed(overallStart, gotFirstByte)
	}

	result := httpCheckResponse{
		Success:    true,
		StatusCode: resp.StatusCode,
		Timing:     timing,
		RemoteIP:   remoteAddr,
	}

	// Extract TLS certificate info if present
	if len(peerCerts) > 0 {
		cert := peerCerts[0]
		daysUntil := int(time.Until(cert.NotAfter).Hours() / 24)
		result.TLS = &httpCheckTLS{
			Subject:         cert.Subject.CommonName,
			Issuer:          cert.Issuer.CommonName,
			Expiry:          cert.NotAfter.UTC().Format(time.RFC3339),
			DaysUntilExpiry: daysUntil,
			Valid:           daysUntil > 0,
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func msElapsed(start, end time.Time) float64 {
	return float64(end.Sub(start).Microseconds()) / 1000.0
}
