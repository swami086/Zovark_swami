package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================
// AUDIT LOG EXPORT AND SIEM FORWARDING (Issue #7)
// ============================================================

// auditExportHandler exports audit logs with filtering and format support.
// GET /api/v1/audit/export
// Query params: start_date, end_date, event_type, format (json/csv/cef), page, limit
func auditExportHandler(c *gin.Context) {
	tenantID := c.MustGet("tenant_id").(string)

	// Parse query parameters
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")
	eventType := c.Query("event_type")
	format := c.DefaultQuery("format", "json")
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "100")

	page := 1
	limit := 100
	fmt.Sscanf(pageStr, "%d", &page)
	fmt.Sscanf(limitStr, "%d", &limit)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	offset := (page - 1) * limit

	// Build query
	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	argN := 2

	if startDate != "" {
		where += fmt.Sprintf(" AND created_at >= $%d", argN)
		args = append(args, startDate)
		argN++
	}
	if endDate != "" {
		where += fmt.Sprintf(" AND created_at <= ($%d::date + interval '1 day')", argN)
		args = append(args, endDate)
		argN++
	}
	if eventType != "" {
		where += fmt.Sprintf(" AND action = $%d", argN)
		args = append(args, eventType)
		argN++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM agent_audit_log " + where
	err := dbPool.QueryRow(c.Request.Context(), countQuery, args...).Scan(&total)
	if err != nil {
		log.Printf("Audit export count error: %v", err)
		respondError(c, http.StatusInternalServerError, "QUERY_FAILED", "failed to count audit records")
		return
	}

	// Fetch data
	dataArgs := make([]interface{}, len(args))
	copy(dataArgs, args)
	dataArgs = append(dataArgs, limit, offset)

	query := fmt.Sprintf(
		"SELECT id, action, resource_type, resource_id, details, ip_address, user_agent, created_at FROM agent_audit_log %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		where, argN, argN+1,
	)

	rows, err := dbPool.Query(c.Request.Context(), query, dataArgs...)
	if err != nil {
		log.Printf("Audit export query error: %v", err)
		respondError(c, http.StatusInternalServerError, "QUERY_FAILED", "failed to query audit records")
		return
	}
	defer rows.Close()

	var records []map[string]interface{}
	for rows.Next() {
		var id, action, resourceType string
		var resourceID *string
		var details map[string]interface{}
		var ipAddress, userAgent *string
		var createdAt time.Time

		if err := rows.Scan(&id, &action, &resourceType, &resourceID, &details, &ipAddress, &userAgent, &createdAt); err != nil {
			log.Printf("Audit export scan error: %v", err)
			continue
		}

		record := map[string]interface{}{
			"id":            id,
			"event_type":    action,
			"resource_type": resourceType,
			"resource_id":   resourceID,
			"details":       details,
			"ip_address":    ipAddress,
			"user_agent":    userAgent,
			"tenant_id":     tenantID,
			"created_at":    createdAt.Format(time.RFC3339),
		}
		records = append(records, record)
	}

	if records == nil {
		records = []map[string]interface{}{}
	}

	// Format output
	switch format {
	case "csv":
		columns := []string{"id", "event_type", "resource_type", "resource_id", "ip_address", "user_agent", "created_at"}
		csv := recordsToCSV(records, columns)
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=audit_export.csv")
		c.String(http.StatusOK, csv)

	case "cef":
		var cefLines []string
		for _, record := range records {
			cefLines = append(cefLines, toCEF(record))
		}
		c.Header("Content-Type", "text/plain")
		c.Header("Content-Disposition", "attachment; filename=audit_export.cef")
		c.String(http.StatusOK, strings.Join(cefLines, "\n")+"\n")

	default: // json
		respondList(c, gin.H{"audit_records": records}, page, limit, total)
	}
}
