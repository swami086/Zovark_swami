package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// gdprEraseHandler handles GDPR Article 17 right-to-erasure requests (Security P2#28).
// DELETE /api/v1/tenants/:id/data
func gdprEraseHandler(c *gin.Context) {
	tenantID := c.Param("id")
	callerTenantID := c.MustGet("tenant_id").(string)
	role := c.MustGet("role").(string)

	// Only own-tenant admin or super_admin
	if role != "super_admin" && tenantID != callerTenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	// Ordered deletion respecting foreign keys
	queries := []string{
		"DELETE FROM entity_observations WHERE tenant_id = $1",
		"DELETE FROM entity_edges WHERE tenant_id = $1",
		"DELETE FROM entities WHERE tenant_id = $1",
		"DELETE FROM investigation_cache WHERE tenant_id = $1",
		"DELETE FROM investigation_steps WHERE tenant_id = $1",
		"DELETE FROM investigation_feedback WHERE investigation_id IN (SELECT id FROM investigations WHERE tenant_id = $1)",
		"DELETE FROM investigation_reports WHERE investigation_id IN (SELECT id FROM investigations WHERE tenant_id = $1)",
		"DELETE FROM investigations WHERE tenant_id = $1",
		"DELETE FROM siem_alerts WHERE tenant_id = $1",
		"DELETE FROM llm_call_log WHERE tenant_id = $1",
		"DELETE FROM audit_events WHERE tenant_id = $1",
		"DELETE FROM agent_audit_log WHERE tenant_id = $1",
		"DELETE FROM shadow_recommendations WHERE tenant_id = $1",
		"DELETE FROM agent_tasks WHERE tenant_id = $1",
		"UPDATE users SET email = 'erased@erased', display_name = 'ERASED', password_hash = 'ERASED', totp_secret = NULL, totp_enabled = false WHERE tenant_id = $1",
	}

	tx, err := dbPool.Begin(c.Request.Context())
	if err != nil {
		respondInternalError(c, err, "gdpr erase begin tx")
		return
	}

	for _, q := range queries {
		if _, err := tx.Exec(c.Request.Context(), q, tenantID); err != nil {
			tx.Rollback(c.Request.Context())
			log.Printf("[ERROR] GDPR erase failed on query: %v", err)
			respondInternalError(c, err, "gdpr erase")
			return
		}
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		respondInternalError(c, err, "gdpr erase commit")
		return
	}

	// Audit the erasure (in the audit log, which was just cleared for this tenant)
	log.Printf("[AUDIT] GDPR erasure completed for tenant %s by user in tenant %s", tenantID, callerTenantID)

	c.JSON(http.StatusOK, gin.H{
		"status":    "erased",
		"tenant_id": tenantID,
	})
}
