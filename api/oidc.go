package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ============================================================
// SSO/OIDC INTEGRATION (Issue #1)
// Lightweight OIDC implementation using net/http
// ============================================================

// OIDCConfig holds the OIDC provider configuration.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	RoleClaimKey string // OIDC claim key to map to HYDRA roles
}

// OIDCDiscovery represents the OpenID Connect Discovery document.
type OIDCDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

// OIDCTokenResponse represents the token endpoint response.
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

var (
	oidcConfig    *OIDCConfig
	oidcDiscovery *OIDCDiscovery
)

// initOIDC initializes the OIDC configuration from environment variables.
func initOIDC() {
	issuer := getEnvOrDefault("OIDC_ISSUER_URL", "")
	if issuer == "" {
		log.Println("OIDC not configured (OIDC_ISSUER_URL not set). SSO disabled.")
		return
	}

	oidcConfig = &OIDCConfig{
		IssuerURL:    issuer,
		ClientID:     getEnvOrDefault("OIDC_CLIENT_ID", ""),
		ClientSecret: getEnvOrDefault("OIDC_CLIENT_SECRET", ""),
		RedirectURI:  getEnvOrDefault("OIDC_REDIRECT_URI", "http://localhost:8090/api/v1/auth/callback"),
		RoleClaimKey: getEnvOrDefault("OIDC_ROLE_CLAIM_KEY", "role"),
	}

	// Discover OIDC endpoints
	discovery, err := discoverOIDC(oidcConfig.IssuerURL)
	if err != nil {
		log.Printf("OIDC discovery failed: %v. SSO will be unavailable.", err)
		oidcConfig = nil
		return
	}
	oidcDiscovery = discovery
	log.Printf("OIDC configured: issuer=%s", oidcConfig.IssuerURL)
}

// discoverOIDC fetches the OpenID Connect discovery document.
func discoverOIDC(issuerURL string) (*OIDCDiscovery, error) {
	wellKnownURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	return &discovery, nil
}

// generatePKCE creates a code verifier and challenge for PKCE.
func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)

	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge
}

// generateState creates a random state parameter for CSRF protection.
func generateState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ssoLoginHandler initiates the OIDC authorization code flow.
// GET /api/v1/auth/sso/login
func ssoLoginHandler(c *gin.Context) {
	if oidcConfig == nil || oidcDiscovery == nil {
		respondError(c, http.StatusServiceUnavailable, "SSO_NOT_CONFIGURED",
			"SSO/OIDC is not configured. Use email/password authentication.")
		return
	}

	verifier, challenge := generatePKCE()
	state := generateState()

	// Store verifier and state in a short-lived cookie
	c.SetCookie("oidc_verifier", verifier, 600, "/", "", false, true)
	c.SetCookie("oidc_state", state, 600, "/", "", false, true)

	// Build authorization URL
	params := url.Values{
		"client_id":             {oidcConfig.ClientID},
		"redirect_uri":         {oidcConfig.RedirectURI},
		"response_type":        {"code"},
		"scope":                {"openid email profile"},
		"state":                {state},
		"code_challenge":       {challenge},
		"code_challenge_method": {"S256"},
	}

	authURL := oidcDiscovery.AuthorizationEndpoint + "?" + params.Encode()
	c.Redirect(http.StatusFound, authURL)
}

// ssoCallbackHandler handles the OIDC callback, exchanges code for tokens, provisions user.
// GET /api/v1/auth/callback
func ssoCallbackHandler(c *gin.Context) {
	if oidcConfig == nil || oidcDiscovery == nil {
		respondError(c, http.StatusServiceUnavailable, "SSO_NOT_CONFIGURED",
			"SSO/OIDC is not configured.")
		return
	}

	// Validate state
	state := c.Query("state")
	savedState, err := c.Cookie("oidc_state")
	if err != nil || state != savedState {
		respondError(c, http.StatusBadRequest, "INVALID_STATE", "Invalid or missing state parameter")
		return
	}

	// Get authorization code
	code := c.Query("code")
	if code == "" {
		errMsg := c.Query("error_description")
		if errMsg == "" {
			errMsg = c.Query("error")
		}
		respondError(c, http.StatusBadRequest, "AUTH_FAILED", "Authorization failed: "+errMsg)
		return
	}

	// Get PKCE verifier
	verifier, err := c.Cookie("oidc_verifier")
	if err != nil {
		respondError(c, http.StatusBadRequest, "MISSING_VERIFIER", "PKCE verifier not found")
		return
	}

	// Exchange code for tokens
	tokenResp, err := exchangeCode(code, verifier)
	if err != nil {
		log.Printf("OIDC token exchange failed: %v", err)
		respondError(c, http.StatusInternalServerError, "TOKEN_EXCHANGE_FAILED", "Failed to exchange authorization code")
		return
	}

	// Parse ID token claims (without signature verification for simplicity with local IdPs)
	claims, err := parseIDTokenClaims(tokenResp.IDToken)
	if err != nil {
		log.Printf("OIDC ID token parse failed: %v", err)
		respondError(c, http.StatusInternalServerError, "TOKEN_PARSE_FAILED", "Failed to parse ID token")
		return
	}

	// Extract user info from claims
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	sub, _ := claims["sub"].(string)

	if email == "" {
		// Fall back to userinfo endpoint
		userInfo, uiErr := fetchUserInfo(tokenResp.AccessToken)
		if uiErr == nil {
			if e, ok := userInfo["email"].(string); ok {
				email = e
			}
			if n, ok := userInfo["name"].(string); ok && name == "" {
				name = n
			}
		}
	}

	if email == "" {
		respondError(c, http.StatusBadRequest, "MISSING_EMAIL", "Email claim not found in ID token")
		return
	}

	// Map OIDC role claim to HYDRA role
	role := "analyst" // Default role
	if roleClaim, ok := claims[oidcConfig.RoleClaimKey]; ok {
		if r, ok := roleClaim.(string); ok {
			switch r {
			case "admin", "administrator":
				role = "admin"
			case "viewer", "readonly":
				role = "viewer"
			default:
				role = "analyst"
			}
		}
	}

	// JIT (Just-In-Time) user provisioning
	user, err := jitProvision(c.Request.Context(), email, name, sub, role)
	if err != nil {
		log.Printf("OIDC JIT provisioning failed: %v", err)
		respondError(c, http.StatusInternalServerError, "PROVISION_FAILED", "Failed to provision user")
		return
	}

	// Issue HYDRA JWT
	jwtClaims := CustomClaims{
		TenantID: user.TenantID,
		UserID:   user.ID,
		Email:    user.Email,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	tokenString, err := token.SignedString([]byte(appConfig.JWTSecret))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "TOKEN_GENERATION_FAILED", "Failed to generate JWT")
		return
	}

	// Clear OIDC cookies
	c.SetCookie("oidc_verifier", "", -1, "/", "", false, true)
	c.SetCookie("oidc_state", "", -1, "/", "", false, true)

	respondOK(c, gin.H{
		"token": tokenString,
		"user": map[string]interface{}{
			"id":        user.ID,
			"email":     user.Email,
			"role":      user.Role,
			"tenant_id": user.TenantID,
			"name":      user.Name,
			"sso":       true,
		},
	})
}

// exchangeCode exchanges an authorization code for tokens at the token endpoint.
func exchangeCode(code, verifier string) (*OIDCTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {oidcConfig.RedirectURI},
		"client_id":     {oidcConfig.ClientID},
		"client_secret": {oidcConfig.ClientSecret},
		"code_verifier": {verifier},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(oidcDiscovery.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// parseIDTokenClaims extracts claims from a JWT ID token without full verification.
// In production, you would verify the signature against the IdP's JWKS.
func parseIDTokenClaims(idToken string) (map[string]interface{}, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part)
	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try without padding
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode payload: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims, nil
}

// fetchUserInfo calls the OIDC userinfo endpoint.
func fetchUserInfo(accessToken string) (map[string]interface{}, error) {
	if oidcDiscovery.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not available")
	}

	req, err := http.NewRequest("GET", oidcDiscovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

// OIDCUser represents a provisioned user from OIDC.
type OIDCUser struct {
	ID       string
	Email    string
	Name     string
	Role     string
	TenantID string
}

// jitProvision performs Just-In-Time user provisioning.
// If the user exists, returns existing user. Otherwise, creates a new user.
func jitProvision(ctx context.Context, email, name, externalID, role string) (*OIDCUser, error) {
	// Check if user already exists
	var user OIDCUser
	err := dbPool.QueryRow(ctx,
		"SELECT id, email, display_name, role, tenant_id FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.TenantID)

	if err == nil {
		// User exists, update external_auth_id and last login
		_, _ = dbPool.Exec(ctx,
			"UPDATE users SET external_auth_id = $1, last_login_at = NOW() WHERE id = $2",
			externalID, user.ID,
		)
		return &user, nil
	}

	// JIT provision: create user in default tenant
	// Look for the first active tenant, or use hydra-dev
	var tenantID string
	err = dbPool.QueryRow(ctx,
		"SELECT id FROM tenants WHERE slug = 'hydra-dev' AND is_active = true",
	).Scan(&tenantID)
	if err != nil {
		// Use first active tenant
		err = dbPool.QueryRow(ctx,
			"SELECT id FROM tenants WHERE is_active = true ORDER BY created_at ASC LIMIT 1",
		).Scan(&tenantID)
		if err != nil {
			return nil, fmt.Errorf("no active tenant found for JIT provisioning")
		}
	}

	if name == "" {
		name = email
	}

	userID := uuid.New().String()
	_, err = dbPool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, display_name, role, external_auth_id, is_active)
		 VALUES ($1, $2, $3, $4, $5, $6, true)`,
		userID, tenantID, email, name, role, externalID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &OIDCUser{
		ID:       userID,
		Email:    email,
		Name:     name,
		Role:     role,
		TenantID: tenantID,
	}, nil
}
