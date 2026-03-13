package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=6"`
	DisplayName string `json:"display_name" binding:"required"`
	TenantID    string `json:"tenant_id" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	TOTPCode string `json:"totp_code"` // Optional TOTP code for 2FA
}

type CustomClaims struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func registerHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	userID := uuid.New().String()

	_, err = dbPool.Exec(context.Background(),
		"INSERT INTO users (id, tenant_id, email, display_name, role, password_hash) VALUES ($1, $2, $3, $4, $5, $6)",
		userID, req.TenantID, req.Email, req.DisplayName, "analyst", string(hashedPassword))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user or user already exists"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user": map[string]interface{}{
			"id":        userID,
			"email":     req.Email,
			"role":      "analyst",
			"tenant_id": req.TenantID,
		},
	})
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user struct {
		ID           string
		TenantID     string
		Email        string
		Role         string
		PasswordHash string
	}

	err := dbPool.QueryRow(context.Background(),
		"SELECT id, tenant_id, email, role, password_hash FROM users WHERE email = $1", req.Email).
		Scan(&user.ID, &user.TenantID, &user.Email, &user.Role, &user.PasswordHash)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Check account lockout
	if checkAccountLocked(req.Email) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked due to failed login attempts"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		recordFailedLogin(req.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Check TOTP 2FA if enabled
	totpValid, totpErr := checkTOTP(user.ID, req.TOTPCode)
	if totpErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify 2FA"})
		return
	}
	if !totpValid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":         "TOTP code required",
			"totp_required": true,
		})
		return
	}

	recordSuccessfulLogin(req.Email)

	// Access token: 15 minutes
	accessClaims := CustomClaims{
		TenantID: user.TenantID,
		UserID:   user.ID,
		Email:    user.Email,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "access",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(appConfig.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	// Refresh token: 7 days
	refreshClaims := CustomClaims{
		TenantID: user.TenantID,
		UserID:   user.ID,
		Email:    user.Email,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "refresh",
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(appConfig.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	// Set refresh token as httpOnly cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60,
		Path:     "/",
	})

	c.JSON(http.StatusOK, gin.H{
		"token": accessTokenString,
		"user": map[string]interface{}{
			"id":        user.ID,
			"email":     user.Email,
			"role":      user.Role,
			"tenant_id": user.TenantID,
		},
	})
}

// refreshHandler issues a new access token from a valid refresh token cookie.
// POST /api/v1/auth/refresh
func refreshHandler(c *gin.Context) {
	cookie, err := c.Cookie("refresh_token")
	if err != nil || cookie == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no refresh token"})
		return
	}

	token, err := jwt.ParseWithClaims(cookie, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(appConfig.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || claims.Subject != "refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token type"})
		return
	}

	// Issue new access token (15 min)
	accessClaims := CustomClaims{
		TenantID: claims.TenantID,
		UserID:   claims.UserID,
		Email:    claims.Email,
		Role:     claims.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "access",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(appConfig.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": accessTokenString,
		"user": map[string]interface{}{
			"id":        claims.UserID,
			"email":     claims.Email,
			"role":      claims.Role,
			"tenant_id": claims.TenantID,
		},
	})
}

// logoutHandler clears the refresh token cookie.
// POST /api/v1/auth/logout
func logoutHandler(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Path:     "/",
	})
	c.JSON(http.StatusOK, gin.H{"status": "logged out"})
}
