package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	appConfig *Config
	startTime = time.Now()
)

type Config struct {
	Port             string
	DatabaseURL      string
	TemporalAddress  string
	LiteLLMMasterKey string
	JWTSecret        string
	// OIDC/SSO configuration
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURI  string
	OIDCRoleClaimKey string
	// Vault
	VaultAddr  string
	VaultToken string
	// Redis
	RedisURL string
	// NATS
	NATSURL string
}

func init() {
	appConfig = &Config{
		Port:             getEnvOrDefault("PORT", "8090"),
		DatabaseURL:      getEnvOrDefault("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"),
		TemporalAddress:  getEnvOrDefault("TEMPORAL_ADDRESS", "temporal:7233"),
		LiteLLMMasterKey: getEnvOrDefault("LITELLM_MASTER_KEY", ""),
		JWTSecret:        getEnvOrDefault("JWT_SECRET", ""),
		// OIDC
		OIDCIssuerURL:    getEnvOrDefault("OIDC_ISSUER_URL", ""),
		OIDCClientID:     getEnvOrDefault("OIDC_CLIENT_ID", ""),
		OIDCClientSecret: getEnvOrDefault("OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURI:  getEnvOrDefault("OIDC_REDIRECT_URI", "http://localhost:8090/api/v1/auth/callback"),
		OIDCRoleClaimKey: getEnvOrDefault("OIDC_ROLE_CLAIM_KEY", "role"),
		// Vault
		VaultAddr:  getEnvOrDefault("VAULT_ADDR", ""),
		VaultToken: getEnvOrDefault("VAULT_TOKEN", ""),
		// Redis
		RedisURL: getEnvOrDefault("REDIS_URL", "redis:6379"),
		// NATS
		NATSURL: getEnvOrDefault("NATS_URL", ""),
	}
}

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func main() {
	// Check for CLI commands
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		cmd := "up"
		if len(os.Args) > 2 {
			cmd = os.Args[2]
		}
		// Initialize DB for migration commands
		initVault()
		defer stopVault()
		appConfig.DatabaseURL = GetSecret("database_url", "DATABASE_URL", appConfig.DatabaseURL)
		appConfig.JWTSecret = GetSecret("jwt_secret", "JWT_SECRET", appConfig.JWTSecret)
		if err := initDB(appConfig.DatabaseURL); err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}
		defer closeDB()
		runMigrations(cmd, os.Args[3:])
		return
	}

	log.Println("Starting Hydra API Gateway...")

	// Initialize Vault (for secrets management — must come before DB init)
	initVault()
	defer stopVault()

	// Override config from Vault if available
	appConfig.DatabaseURL = GetSecret("database_url", "DATABASE_URL", appConfig.DatabaseURL)
	appConfig.JWTSecret = GetSecret("jwt_secret", "JWT_SECRET", appConfig.JWTSecret)

	// Enforce strong JWT secret
	if len(appConfig.JWTSecret) < 32 {
		log.Fatal("FATAL: JWT_SECRET must be at least 32 characters. Generate with: openssl rand -base64 64")
	}

	// Initialize Database connection
	err := initDB(appConfig.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer closeDB()

	// Initialize Redis for rate limiting
	initRedis()

	// Initialize Temporal client
	err = initTemporal(appConfig.TemporalAddress)
	if err != nil {
		log.Fatalf("Failed to initialize Temporal client: %v", err)
	}
	defer closeTemporal()

	// Initialize OIDC (SSO)
	initOIDC()

	// Initialize NATS (alert publishing — optional)
	natsClient = initNATS()
	if natsClient != nil {
		defer natsClient.Close()
	}

	// Setup Gin router
	router := gin.Default()

	// Middlewares
	router.Use(corsMiddleware())
	router.Use(securityHeadersMiddleware())
	router.Use(loggingMiddleware())
	router.Use(maxBodySizeMiddleware(10 << 20)) // 10MB global limit

	// Public routes
	router.GET("/health", healthCheckHandler)

	// Public auth routes (rate limited)
	auth := router.Group("/api/v1/auth")
	auth.Use(authRateLimitMiddleware())
	{
		auth.POST("/login", loginHandler)
		auth.POST("/register", registerHandler)
		auth.POST("/refresh", refreshHandler)
		auth.POST("/logout", logoutHandler)
		// SSO/OIDC routes (public)
		auth.GET("/sso/login", ssoLoginHandler)
		auth.GET("/callback", ssoCallbackHandler)
	}

	// Public webhook route (HMAC-validated, no JWT)
	router.POST("/api/v1/webhooks/:source_id/alert", webhookAlertHandler)

	// Protected API routes
	api := router.Group("/api/v1")
	api.Use(authMiddleware())
	api.Use(tenantRateLimitMiddleware())
	api.Use(auditMiddleware())
	{
		// Anyone authenticated
		api.GET("/tasks", listTasksHandler)
		api.GET("/tasks/:id", getTaskHandler)
		api.GET("/tasks/:id/audit", getTaskAuditHandler)
		api.GET("/tasks/:id/steps", getTaskStepsHandler)
		api.GET("/tasks/:id/timeline", getTaskTimelineHandler)
		api.GET("/tasks/:id/stream", taskSSEHandler)
		api.GET("/stats", getStatsHandler)
		api.GET("/playbooks", listPlaybooksHandler)
		api.GET("/skills", listSkillsHandler)
		api.GET("/me", getMeHandler)
		api.GET("/log-sources", listLogSourcesHandler)
		api.GET("/siem-alerts", listSIEMalertsHandler)
		api.GET("/notifications", getNotificationsHandler)

		// Analyst + Admin (LLM-triggering endpoints have token quota check)
		api.POST("/tasks", requireRole("admin", "analyst", "api_key"), checkTokenQuota(), createTaskHandler)
		api.POST("/tasks/bulk", requireRole("admin", "analyst", "api_key"), checkTokenQuota(), bulkCreateTasksHandler)
		api.POST("/tasks/upload", requireRole("admin", "analyst"), checkTokenQuota(), uploadTaskHandler)
		api.POST("/siem-alerts/:id/investigate", requireRole("admin", "analyst"), checkTokenQuota(), investigateAlertHandler)
		api.POST("/investigations/:id/feedback", requireRole("admin", "analyst"), submitFeedbackHandler)

		// TOTP 2FA (authenticated users)
		api.POST("/auth/totp/setup", totpSetupHandler)
		api.POST("/auth/totp/verify", totpVerifyHandler)

		// Sandbox execution (DPO pipeline)
		api.POST("/sandbox/execute", requireRole("admin", "analyst"), sandboxExecuteHandler)

		// Feedback stats (admin only)
		api.GET("/feedback/stats", requireRole("admin"), getFeedbackStatsHandler)

		// Analytics — feedback insights (all tenant-scoped)
		api.GET("/analytics/feedback/summary", feedbackSummaryHandler)
		api.GET("/analytics/feedback/rules", feedbackRulesHandler)
		api.GET("/analytics/feedback/analysts", feedbackAnalystsHandler)

		// Webhook endpoints (authenticated)
		api.GET("/webhooks/endpoints", listWebhookEndpointsHandler)
		api.GET("/webhooks/deliveries", listWebhookDeliveriesHandler)

		// Audit export (admin only)
		api.GET("/audit/export", requireRole("admin"), auditExportHandler)

		// API key management (admin only)
		api.POST("/api-keys", requireRole("admin"), createAPIKeyHandler)
		api.GET("/api-keys", requireRole("admin"), listAPIKeysHandler)
		api.DELETE("/api-keys/:id", requireRole("admin"), deleteAPIKeyHandler)

		// Admin only — DB-backed task-level approvals (Temporal signal gate)
		api.GET("/approvals/pending", requireRole("admin"), getPendingApprovalsHandler)
		api.POST("/approvals/:id/decide", requireRole("admin"), decideApprovalHandler)

		// MCP human-in-the-loop approval gate — Redis-backed workflow approvals
		// Any authenticated caller may request an approval or check its status.
		api.POST("/mcp/approvals/request", requestMCPApprovalHandler)
		api.GET("/mcp/approvals/check/:token", checkMCPApprovalHandler)
		// Admin-only: list, lookup, and decide on pending approvals.
		api.GET("/mcp/approvals/pending", requireRole("admin"), listMCPApprovalsHandler)
		api.GET("/mcp/approvals/id/:approval_id", requireRole("admin"), getMCPApprovalByIDHandler)
		api.POST("/mcp/approvals/:token/decide", requireRole("admin"), decideMCPApprovalHandler)

		api.POST("/playbooks", requireRole("admin"), createPlaybookHandler)
		api.PUT("/playbooks/:id", requireRole("admin"), updatePlaybookHandler)
		api.DELETE("/playbooks/:id", requireRole("admin"), deletePlaybookHandler)
		api.POST("/log-sources", requireRole("admin"), createLogSourceHandler)
		api.PUT("/log-sources/:id", requireRole("admin"), updateLogSourceHandler)
		api.DELETE("/log-sources/:id", requireRole("admin"), deleteLogSourceHandler)

		// Tenant management (admin only)
		api.GET("/tenants", requireRole("admin"), listTenantsHandler)
		api.GET("/tenants/:id", requireRole("admin"), getTenantHandler)
		api.POST("/tenants", requireRole("admin"), createTenantHandler)
		api.PUT("/tenants/:id", requireRole("admin"), updateTenantHandler)
		api.DELETE("/tenants/:id/data", requireRole("admin"), gdprEraseHandler)

		// Webhook endpoint management (admin only)
		api.POST("/webhooks/endpoints", requireRole("admin"), createWebhookEndpointHandler)
		api.PUT("/webhooks/endpoints/:id", requireRole("admin"), updateWebhookEndpointHandler)
		api.DELETE("/webhooks/endpoints/:id", requireRole("admin"), deleteWebhookEndpointHandler)

		// Model registry (admin only)
		api.GET("/models", requireRole("admin"), listModelsHandler)
		api.POST("/models", requireRole("admin"), createModelHandler)
		api.PUT("/models/:id", requireRole("admin"), updateModelHandler)

		// A/B testing (admin only)
		api.GET("/models/ab-tests", requireRole("admin"), listABTestsHandler)
		api.POST("/models/ab-tests", requireRole("admin"), createABTestHandler)
		api.POST("/models/ab-tests/:id/complete", requireRole("admin"), completeABTestHandler)

		// Data retention (admin only)
		api.GET("/retention-policies", requireRole("admin"), listRetentionPoliciesHandler)
		api.PUT("/retention-policies/:id", requireRole("admin"), updateRetentionPolicyHandler)

		// SIEM Ingest — vendor-specific webhook receivers (analyst + admin)
		api.POST("/ingest/splunk", requireRole("admin", "analyst", "api_key"), checkTokenQuota(), splunkIngestHandler)
		api.POST("/ingest/elastic", requireRole("admin", "analyst", "api_key"), checkTokenQuota(), elasticIngestHandler)
		api.GET("/ingest/health", ingestHealthHandler)

		// Integration management (admin only)
		api.POST("/integrations/slack/test", requireRole("admin"), testSlackWebhookHandler)
		api.PUT("/integrations/slack", requireRole("admin"), configureSlackWebhookHandler)
		api.POST("/integrations/teams/test", requireRole("admin"), testTeamsWebhookHandler)
		api.PUT("/integrations/teams", requireRole("admin"), configureTeamsWebhookHandler)

		// Shadow mode (authenticated users)
		api.GET("/shadow/recommendations", listShadowRecommendationsHandler)
		api.GET("/shadow/recommendations/:id", getShadowRecommendationHandler)
		api.POST("/shadow/recommendations/:id/decide", decideShadowRecommendationHandler)
		api.GET("/shadow/conformance", getShadowConformanceHandler)
		api.GET("/shadow/status", getShadowStatusHandler)

		// Automation controls (authenticated for GET, admin for mutations)
		api.GET("/automation/controls", listAutomationControlsHandler)
		api.POST("/automation/controls", requireRole("admin"), upsertAutomationControlHandler)
		api.POST("/automation/kill", requireRole("admin"), emergencyKillHandler)
		api.POST("/automation/resume", requireRole("admin"), resumeAutomationHandler)
		api.GET("/automation/audit", requireRole("admin"), getKillSwitchAuditHandler)

		// Token quotas (authenticated for GET, admin for mutations)
		api.GET("/quotas", getTokenQuotaHandler)
		api.PUT("/quotas", requireRole("admin"), updateTokenQuotaHandler)
		api.POST("/quotas/circuit-breaker", requireRole("admin"), circuitBreakerHandler)
		api.GET("/quotas/usage", getTokenUsageHandler)

		// Metrics (admin only)
		api.GET("/metrics", requireRole("admin"), metricsHandler)

		// Sprint 1K: Cross-tenant intelligence (authenticated users)
		api.GET("/intelligence/top-threats", topThreatsHandler)
		api.GET("/intelligence/stats", intelligenceStatsHandler)

		// Sprint 2A: Detection engine (authenticated for GET, admin for mutations)
		api.GET("/detections/rules", listDetectionRulesHandler)
		api.GET("/detections/stats", detectionStatsHandler)

		// Sprint 2B: SOAR response playbooks
		api.GET("/response/playbooks", listResponsePlaybooksHandler)
		api.POST("/response/playbooks", requireRole("admin"), createResponsePlaybookHandler)
		api.PUT("/response/playbooks/:id", requireRole("admin"), updateResponsePlaybookHandler)
		api.DELETE("/response/playbooks/:id", requireRole("admin"), deleteResponsePlaybookHandler)
		api.GET("/response/executions", listResponseExecutionsHandler)
		api.GET("/response/executions/:id", getResponseExecutionHandler)
		api.POST("/response/executions/:id/approve", requireRole("admin"), approveResponseExecutionHandler)
		api.POST("/response/executions/:id/rollback", requireRole("admin"), rollbackResponseExecutionHandler)
	}

	// Start server
	log.Printf("Listening and serving HTTP on :%s\n", appConfig.Port)
	if err := router.Run(":" + appConfig.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
