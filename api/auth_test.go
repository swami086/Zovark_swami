package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestAuthMiddleware_ValidJWT verifies that a properly signed, non-expired
// access token is accepted by authMiddleware.  Without a database the handler
// will return 500 rather than 200, but it must not return 401.
func TestAuthMiddleware_ValidJWT(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "test@zovarc.local", "admin")
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, token)
	if w.Code == http.StatusUnauthorized {
		t.Errorf("Valid JWT should not return 401, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestAuthMiddleware_ExpiredJWT verifies that an expired token is rejected
// with 401.
func TestAuthMiddleware_ExpiredJWT(t *testing.T) {
	router := setupTestRouter()
	token := createExpiredJWT("tenant-1", "user-1", "admin")
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, token)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expired JWT should return 401, got %d", w.Code)
	}
}

// TestAuthMiddleware_MissingJWT verifies that a request with no Authorization
// header is rejected with 401.
func TestAuthMiddleware_MissingJWT(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Missing JWT should return 401, got %d", w.Code)
	}
}

// TestAuthMiddleware_TamperedJWT verifies that altering the token signature
// causes a 401 rejection.
func TestAuthMiddleware_TamperedJWT(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "test@zovarc.local", "admin")
	// Replace the last 5 characters of the base64 signature with garbage.
	tampered := token[:len(token)-5] + "XXXXX"
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, tampered)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Tampered JWT should return 401, got %d", w.Code)
	}
}

// TestAuthMiddleware_MalformedBearerHeader verifies that Authorization headers
// with the wrong format (no prefix, wrong prefix) are rejected with 401.
func TestAuthMiddleware_MalformedBearerHeader(t *testing.T) {
	router := setupTestRouter()
	token := createTestJWT("tenant-1", "user-1", "test@zovarc.local", "admin")

	cases := []struct {
		name        string
		headerValue string
	}{
		{"no Bearer prefix", token},
		{"wrong prefix Token", "Token " + token},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
			req.Header.Set("Authorization", tc.headerValue)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("Malformed header (%s) should return 401, got %d", tc.name, w.Code)
			}
		})
	}
}

// TestAuthMiddleware_WrongSigningMethod signs a token with HS384 and documents
// the current behaviour.  authMiddleware checks for (*jwt.SigningMethodHMAC),
// which HS384 also satisfies, so HS384 tokens are currently accepted.  This
// test acts as a canary: if the middleware is tightened to HS256-only the log
// line below will fire and the assertion should be updated.
func TestAuthMiddleware_WrongSigningMethod(t *testing.T) {
	router := setupTestRouter()
	claims := CustomClaims{
		TenantID: "tenant-1",
		UserID:   "user-1",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "access",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	tokenString, _ := token.SignedString([]byte(appConfig.JWTSecret))
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, tokenString)
	if w.Code == http.StatusUnauthorized {
		t.Logf("INFO: HS384 token is now rejected (401) — middleware has been tightened to HS256-only")
	}
}

// TestAuthMiddleware_RefreshTokenAsAccess documents that refresh tokens
// (Subject="refresh") currently pass authMiddleware because the middleware does
// not validate the Subject claim.  This is a known security gap (the Subject
// check happens only in refreshHandler itself).  If the gap is closed in the
// future this test will log a success message.
func TestAuthMiddleware_RefreshTokenAsAccess(t *testing.T) {
	claims := CustomClaims{
		TenantID: "tenant-1",
		UserID:   "user-1",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "refresh",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(appConfig.JWTSecret))
	router := setupTestRouter()
	w := makeRequest(router, "GET", "/api/v1/tenants", nil, tokenString)
	if w.Code == http.StatusUnauthorized {
		t.Logf("INFO: refresh token used as access token is now rejected — gap has been closed")
	} else {
		t.Logf("INFO: refresh token accepted by authMiddleware (known gap — Subject claim not validated)")
	}
}

// TestRefreshHandler_NoCookie verifies that POST /auth/refresh without a
// refresh_token cookie returns 401.
func TestRefreshHandler_NoCookie(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "POST", "/api/v1/auth/refresh", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Refresh without cookie should return 401, got %d", w.Code)
	}
}

// TestLogoutHandler_AlwaysSucceeds verifies that POST /auth/logout returns
// 200 regardless of whether a cookie is present (logout is unconditional).
func TestLogoutHandler_AlwaysSucceeds(t *testing.T) {
	router := setupTestRouter()
	w := makeRequest(router, "POST", "/api/v1/auth/logout", nil, "")
	if w.Code != http.StatusOK {
		t.Errorf("Logout should always return 200, got %d", w.Code)
	}
	body := parseJSON(w)
	if body["status"] != "logged out" {
		t.Errorf("Logout response should have status 'logged out', got: %v", body)
	}
}
