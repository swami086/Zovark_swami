package main

import (
	"encoding/json"
	"net/http"
)

// registerHandlers wires every endpoint behind auth middleware.
func registerHandlers(authToken string, icmpAvailable bool) *http.ServeMux {
	mux := http.NewServeMux()

	auth := authMiddleware(authToken)

	mux.Handle("/ping", auth(http.HandlerFunc(handlePing(icmpAvailable))))
	mux.Handle("/http-check", auth(http.HandlerFunc(handleHTTPCheck)))
	mux.Handle("/dns", auth(http.HandlerFunc(handleDNS)))
	mux.Handle("/tcp", auth(http.HandlerFunc(handleTCP)))
	mux.Handle("/parse-test", auth(http.HandlerFunc(handleParseTest)))
	mux.Handle("/health", auth(http.HandlerFunc(handleHealth(icmpAvailable))))

	return mux
}

// authMiddleware rejects requests without a valid X-Diag-Token header.
// If DIAG_AUTH_TOKEN is empty, ALL requests are rejected.
func authMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "DIAG_AUTH_TOKEN not configured — all requests rejected",
				})
				return
			}
			provided := r.Header.Get("X-Diag-Token")
			if provided != token {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "invalid or missing X-Diag-Token",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// handleHealth returns service status.
func handleHealth(icmpAvailable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":         "ok",
			"service":        "zovark-diagnostics",
			"icmp_available": icmpAvailable,
		})
	}
}

// writeJSON marshals v and writes it with the given status code.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
