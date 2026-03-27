package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================
// CSV AND JSONL EXPORT HELPERS (Issue #14)
// ============================================================

// recordsToCSV converts a slice of maps to CSV format with a header row.
func recordsToCSV(records []map[string]interface{}, columns []string) string {
	if len(records) == 0 {
		return strings.Join(columns, ",") + "\n"
	}

	var sb strings.Builder

	// Header row
	sb.WriteString(strings.Join(columns, ","))
	sb.WriteString("\n")

	// Data rows
	for _, record := range records {
		var vals []string
		for _, col := range columns {
			val := record[col]
			vals = append(vals, csvEscape(val))
		}
		sb.WriteString(strings.Join(vals, ","))
		sb.WriteString("\n")
	}

	return sb.String()
}

// recordsToJSONL converts a slice of maps to newline-delimited JSON.
func recordsToJSONL(records []map[string]interface{}) string {
	var sb strings.Builder
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			continue
		}
		sb.Write(line)
		sb.WriteString("\n")
	}
	return sb.String()
}

// csvEscape formats a value for safe CSV inclusion.
func csvEscape(val interface{}) string {
	if val == nil {
		return ""
	}

	s := fmt.Sprintf("%v", val)

	// Escape if contains comma, quote, or newline
	if strings.ContainsAny(s, ",\"\n\r") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}

	return s
}

// toCEF converts an audit event to Common Event Format (CEF) string for SIEM forwarding.
// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Event Type|Name|Severity|Extension
func toCEF(record map[string]interface{}) string {
	eventType := fmt.Sprintf("%v", record["event_type"])
	severity := "5" // Default medium

	// Map event types to CEF severity
	switch eventType {
	case "investigation_started", "user_login":
		severity = "3"
	case "investigation_completed", "entity_extracted":
		severity = "5"
	case "approval_denied", "injection_detected":
		severity = "8"
	case "approval_timeout":
		severity = "7"
	}

	tenantID := fmt.Sprintf("%v", record["tenant_id"])
	resourceID := fmt.Sprintf("%v", record["resource_id"])
	timestamp := fmt.Sprintf("%v", record["created_at"])

	extension := fmt.Sprintf("dvchost=zovarc-api cs1=%s cs1Label=tenant_id cs2=%s cs2Label=resource_id rt=%s",
		tenantID, resourceID, timestamp)

	if details, ok := record["details"]; ok && details != nil {
		extension += fmt.Sprintf(" msg=%v", details)
	}

	return fmt.Sprintf("CEF:0|ZOVARC|SOC-Platform|1.0|%s|%s|%s|%s",
		eventType, eventType, severity, extension)
}
