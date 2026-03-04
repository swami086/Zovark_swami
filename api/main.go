package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

var (
	appConfig *Config
)

type Config struct {
	Port             string
	DatabaseURL      string
	TemporalAddress  string
	LiteLLMMasterKey string
	JWTSecret        string
}

func init() {
	appConfig = &Config{
		Port:             getEnvOrDefault("PORT", "8090"),
		DatabaseURL:      getEnvOrDefault("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"),
		TemporalAddress:  getEnvOrDefault("TEMPORAL_ADDRESS", "temporal:7233"),
		LiteLLMMasterKey: getEnvOrDefault("LITELLM_MASTER_KEY", ""),
		JWTSecret:        getEnvOrDefault("JWT_SECRET", "hydra-jwt-secret-dev-2026"),
	}
}

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func main() {
	log.Println("Starting Hydra API Gateway...")

	// Initialize Database connection
	err := initDB(appConfig.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer closeDB()

	// Initialize Temporal client
	err = initTemporal(appConfig.TemporalAddress)
	if err != nil {
		log.Fatalf("Failed to initialize Temporal client: %v", err)
	}
	defer closeTemporal()

	// Setup Gin router
	router := gin.Default()

	// Middlewares
	router.Use(corsMiddleware())
	router.Use(loggingMiddleware())

	// Public routes
	router.GET("/health", healthCheckHandler)

	// Public auth routes
	auth := router.Group("/api/v1/auth")
	{
		auth.POST("/login", loginHandler)
		auth.POST("/register", registerHandler)
	}

	// Public webhook route (HMAC-validated, no JWT)
	router.POST("/api/v1/webhooks/:source_id/alert", webhookAlertHandler)

	// Protected API routes
	api := router.Group("/api/v1")
	api.Use(authMiddleware())
	{
		// Anyone authenticated
		api.GET("/tasks", listTasksHandler)
		api.GET("/tasks/:id", getTaskHandler)
		api.GET("/tasks/:id/audit", getTaskAuditHandler)
		api.GET("/tasks/:id/steps", getTaskStepsHandler)
		api.GET("/tasks/:id/timeline", getTaskTimelineHandler)
		api.GET("/stats", getStatsHandler)
		api.GET("/playbooks", listPlaybooksHandler)
		api.GET("/skills", listSkillsHandler)
		api.GET("/me", getMeHandler)
		api.GET("/log-sources", listLogSourcesHandler)
		api.GET("/siem-alerts", listSIEMalertsHandler)
		api.GET("/notifications", getNotificationsHandler)

		// Analyst + Admin
		api.POST("/tasks", requireRole("admin", "analyst"), createTaskHandler)
		api.POST("/tasks/upload", requireRole("admin", "analyst"), uploadTaskHandler)
		api.POST("/siem-alerts/:id/investigate", requireRole("admin", "analyst"), investigateAlertHandler)

		// Admin only
		api.GET("/approvals/pending", requireRole("admin"), getPendingApprovalsHandler)
		api.POST("/approvals/:id/decide", requireRole("admin"), decideApprovalHandler)
		api.POST("/playbooks", requireRole("admin"), createPlaybookHandler)
		api.PUT("/playbooks/:id", requireRole("admin"), updatePlaybookHandler)
		api.DELETE("/playbooks/:id", requireRole("admin"), deletePlaybookHandler)
		api.POST("/log-sources", requireRole("admin"), createLogSourceHandler)
		api.PUT("/log-sources/:id", requireRole("admin"), updateLogSourceHandler)
		api.DELETE("/log-sources/:id", requireRole("admin"), deleteLogSourceHandler)
	}

	// Start server
	log.Printf("Listening and serving HTTP on :%s\n", appConfig.Port)
	if err := router.Run(":" + appConfig.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
