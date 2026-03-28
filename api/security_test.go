package main

import (
	"net/http"
	"strings"
	"testing"
)

// TestSecurityHeaders_CSP verifies that the Content-Security-Policy header is
// present and contains the mandatory directives.
func TestSecurityHeaders_CSP(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header should be present")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP should contain \"default-src 'self'\", got: %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP should contain \"frame-ancestors 'none'\", got: %s", csp)
	}
}

// TestSecurityHeaders_HSTS verifies that the Strict-Transport-Security header
// is present with a one-year max-age.
func TestSecurityHeaders_HSTS(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	hsts := w.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("Strict-Transport-Security should contain max-age=31536000, got: %s", hsts)
	}
}

// TestSecurityHeaders_XFrameOptions verifies that clickjacking protection is
// set to DENY.
func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	xfo := w.Header().Get("X-Frame-Options")
	if xfo != "DENY" {
		t.Errorf("X-Frame-Options should be DENY, got: %s", xfo)
	}
}

// TestSecurityHeaders_ContentTypeOptions verifies MIME-sniffing is disabled.
func TestSecurityHeaders_ContentTypeOptions(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	xcto := w.Header().Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("X-Content-Type-Options should be nosniff, got: %s", xcto)
	}
}

// TestSecurityHeaders_PermissionsPolicy verifies that the Permissions-Policy
// header is present (restricts camera, microphone, geolocation).
func TestSecurityHeaders_PermissionsPolicy(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	pp := w.Header().Get("Permissions-Policy")
	if pp == "" {
		t.Error("Permissions-Policy header should be present")
	}
}

// TestSecurityHeaders_CacheControl verifies that responses are not cached.
func TestSecurityHeaders_CacheControl(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control should contain no-store, got: %s", cc)
	}
}

// TestSecurityHeaders_XSSProtection verifies that the legacy XSS-protection
// header is set.
func TestSecurityHeaders_XSSProtection(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	xss := w.Header().Get("X-XSS-Protection")
	if xss == "" {
		t.Error("X-XSS-Protection header should be present")
	}
}

// TestSecurityHeaders_ReferrerPolicy verifies the referrer policy header.
func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	rp := w.Header().Get("Referrer-Policy")
	if rp == "" {
		t.Error("Referrer-Policy header should be present")
	}
}

// TestSecurityHeaders_PresentOnAuthenticatedEndpoints verifies that security
// headers are set even on protected endpoints (not just /health).
func TestSecurityHeaders_PresentOnAuthenticatedEndpoints(t *testing.T) {
	router := setupTestRouter()
	// No token — will get 401, but headers should still be set by the middleware
	// which runs before the handler aborts.
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for unauthenticated request, got %d", w.Code)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("Security headers should be set even when request is rejected by authMiddleware")
	}
}

// TestErrorResponse_NoDBDetails verifies that when a handler fails due to
// a missing database connection, the response body does not expose internal
// error details such as PostgreSQL error strings, table names, or SQL keywords.
func TestErrorResponse_NoDBDetails(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "test@zovark.local", "admin")
	// List tenants will hit the DB (nil pool) and call respondInternalError.
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, token)
	body := w.Body.String()

	// Patterns that must never appear in a client-facing response.
	leakPatterns := []string{
		"pq:", "pgx:", "SQLSTATE", "relation", "column",
		"constraint", "dial tcp", "connect: connection refused",
	}
	for _, pattern := range leakPatterns {
		if strings.Contains(body, pattern) {
			t.Errorf("Response body leaked internal detail %q: %s", pattern, body[:min(200, len(body))])
		}
	}
}

// min is a helper used only in tests; the standard library min() requires Go 1.21.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
