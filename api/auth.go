package main

import (
	"context"
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

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	claims := CustomClaims{
		TenantID: user.TenantID,
		UserID:   user.ID,
		Email:    user.Email,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(appConfig.JWTSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": map[string]interface{}{
			"id":        user.ID,
			"email":     user.Email,
			"role":      user.Role,
			"tenant_id": user.TenantID,
		},
	})
}
