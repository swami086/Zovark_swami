package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRespondInternalError_GenericMessage verifies that respondInternalError
// always returns HTTP 500 with the fixed generic message "an internal error
// occurred" regardless of what the underlying error is.
func TestRespondInternalError_GenericMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	respondInternalError(c, errors.New(`pq: relation "users" does not exist`), "test context")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "an internal error occurred") {
		t.Errorf("Response should contain \"an internal error occurred\", got: %s", body)
	}
}

// TestRespondInternalError_NeverLeaksTableNames verifies that various
// PostgreSQL error messages are never forwarded to clients.
func TestRespondInternalError_NeverLeaksTableNames(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testErrors := []string{
		`pq: duplicate key value violates unique constraint "users_email_key"`,
		`pgx: relation "agent_tasks" does not exist`,
		`ERROR: column "tenant_id" of relation "investigations" does not exist (SQLSTATE 42703)`,
		"dial tcp postgres:5432: connect: connection refused",
		`pq: insert or update on table "users" violates foreign key constraint "users_tenant_id_fkey"`,
	}

	sensitivePatterns := []string{
		"pq:", "pgx:", "SQLSTATE", "relation", "constraint",
		"dial tcp", "connect: connection refused",
	}

	for _, errMsg := range testErrors {
		t.Run(errMsg[:min(40, len(errMsg))], func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)

			respondInternalError(c, errors.New(errMsg), "test context")

			if w.Code != http.StatusInternalServerError {
				t.Errorf("Expected 500, got %d", w.Code)
			}
			body := w.Body.String()
			for _, pattern := range sensitivePatterns {
				if strings.Contains(body, pattern) {
					t.Errorf("Response leaked sensitive pattern %q for error %q: body=%s",
						pattern, errMsg, body)
				}
			}
		})
	}
}

// TestRespondInternalError_BodyIsValidJSON verifies that the error response
// is well-formed JSON.
func TestRespondInternalError_BodyIsValidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	respondInternalError(c, errors.New("some internal failure"), "test")

	contentType := w.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("Content-Type should be application/json, got: %s", contentType)
	}

	result := parseJSON(w)
	if result == nil {
		t.Error("Response body should be valid JSON")
		return
	}
	if _, hasError := result["error"]; !hasError {
		t.Errorf("JSON response should have an 'error' key, got: %v", result)
	}
}

// TestRespondInternalError_ContextStringNotLeaked verifies that the context
// string passed to respondInternalError (which names the operation that
// failed) is never included in the client response.
func TestRespondInternalError_ContextStringNotLeaked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	respondInternalError(c, errors.New("some error"), "query tenants from database")

	body := w.Body.String()
	if strings.Contains(body, "query tenants from database") {
		t.Errorf("Context string should not appear in client response, got: %s", body)
	}
}

// TestRespondInternalError_NilError verifies that a nil error does not cause
// a panic and still returns 500.
func TestRespondInternalError_NilError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	// Should not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("respondInternalError panicked on nil error: %v", r)
		}
	}()

	respondInternalError(c, nil, "nil error test")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// TestHealthEndpoint_Returns200 is a lightweight sanity check that the health
// endpoint is reachable and returns 200 with the expected status field.
func TestHealthEndpoint_Returns200(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/health", nil, "")
	if w.Code != http.StatusOK {
		t.Errorf("GET /health should return 200, got %d", w.Code)
	}
	body := parseJSON(w)
	if body["status"] != "ok" {
		t.Errorf("Health response should have status 'ok', got: %v", body["status"])
	}
}
