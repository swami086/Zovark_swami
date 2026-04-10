package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		ctx := c.Request.Context()
		attrs := []slog.Attr{
			slog.String("http.method", c.Request.Method),
			slog.String("http.path", c.Request.URL.Path),
			slog.Int("http.status", c.Writer.Status()),
			slog.Duration("duration", latency),
		}
		if sc := oteltrace.SpanFromContext(ctx).SpanContext(); sc.IsValid() {
			attrs = append(attrs, slog.String("trace_id", sc.TraceID().String()))
		}
		if route := c.FullPath(); route != "" {
			attrs = append(attrs, slog.String("http.route", route))
		}
		slog.LogAttrs(ctx, slog.LevelInfo, "http_request", attrs...)
	}
}

func corsMiddleware() gin.HandlerFunc {
	config := cors.DefaultConfig()

	// Read allowed origins from env (comma-separated), default to localhost for dev
	originsEnv := os.Getenv("ZOVARK_CORS_ORIGINS")
	if originsEnv != "" {
		origins := strings.Split(originsEnv, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		config.AllowOrigins = origins
	} else {
		// localhost and 127.0.0.1 are different origins — allow both for dev / embedded browsers
		config.AllowOrigins = []string{
			"http://localhost:3000", "http://127.0.0.1:3000",
			"http://localhost:5173", "http://127.0.0.1:5173",
		}
	}

	config.AllowCredentials = true
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	config.ExposeHeaders = []string{"Set-Cookie", "X-Zovark-Trace-ID", "traceparent", "tracestate"}
	return cors.New(config)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// EventSource cannot set Authorization; allow ?token= for SSE routes only.
		if strings.Contains(c.Request.URL.Path, "/stream") {
			if t := c.Query("token"); t != "" {
				c.Request.Header.Set("Authorization", "Bearer "+t)
			}
		}

		// Check API key first (M2M authentication)
		if authenticateAPIKey(c) {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			return
		}

		tokenString := parts[1]

		jwtCtx, jwtSpan := otel.Tracer("zovark-api").Start(c.Request.Context(), "auth.jwt_validate")
		c.Request = c.Request.WithContext(jwtCtx)
		defer jwtSpan.End()

		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(appConfig.JWTSecret), nil
		})

		if err != nil {
			jwtSpan.RecordError(err)
			jwtSpan.SetStatus(codes.Error, "jwt invalid")
			log.Printf("JWT parsing error: %v", err)
			msg := "Invalid token"
			if strings.Contains(err.Error(), "token is expired") {
				msg = "Token expired"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg})
			return
		}

		if !token.Valid {
			jwtSpan.SetStatus(codes.Error, "jwt not valid")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok {
			jwtSpan.SetStatus(codes.Error, "jwt claims type")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		// Inject tenant and user references into request context
		c.Set("tenant_id", claims.TenantID)
		c.Set("user_id", claims.UserID)
		c.Set("user_role", claims.Role)

		c.Next()
	}
}

func requireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		for _, role := range allowedRoles {
			if roleStr == role {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
	}
}
