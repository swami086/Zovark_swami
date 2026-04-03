package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Top 30 field mappings from worker/stages/normalizer.py, grouped by format.
// Each entry maps a vendor-specific key to Zovark Common Schema (ZCS).

type fieldMapping struct {
	from string
	to   string
}

// Splunk mappings
var splunkMappings = []fieldMapping{
	{"src_ip", "source_ip"},
	{"dest_ip", "destination_ip"},
	{"src_port", "source_port"},
	{"dest_port", "destination_port"},
	{"src_user", "username"},
	{"dest_host", "hostname"},
	{"signature", "rule_name"},
	{"vendor_product", "source"},
	{"src", "source_ip"},
	{"dest", "destination_ip"},
}

// Elastic mappings (flattened dot notation)
var elasticMappings = []fieldMapping{
	{"source.ip", "source_ip"},
	{"destination.ip", "destination_ip"},
	{"user.name", "username"},
	{"host.hostname", "hostname"},
	{"event.action", "action"},
	{"event.severity", "severity"},
	{"rule.name", "rule_name"},
	{"source.port", "source_port"},
	{"destination.port", "destination_port"},
	{"process.name", "process_name"},
}

// Firewall mappings
var firewallMappings = []fieldMapping{
	{"SrcAddr", "source_ip"},
	{"DstAddr", "destination_ip"},
	{"SrcPort", "source_port"},
	{"DstPort", "destination_port"},
	{"Proto", "protocol"},
	{"Action", "action"},
	{"DeviceName", "hostname"},
	{"SignatureName", "rule_name"},
	{"Application", "process_name"},
	{"User", "username"},
}

// allMappings combines all three sets for lookup.
var allMappings = func() map[string]fieldMapping {
	m := make(map[string]fieldMapping)
	for _, fm := range splunkMappings {
		m[fm.from] = fm
	}
	for _, fm := range elasticMappings {
		m[fm.from] = fm
	}
	for _, fm := range firewallMappings {
		m[fm.from] = fm
	}
	return m
}()

// splunkKeys, elasticKeys, firewallKeys for detection
var splunkKeys = func() map[string]bool {
	m := make(map[string]bool)
	for _, fm := range splunkMappings {
		m[fm.from] = true
	}
	return m
}()

var elasticKeys = func() map[string]bool {
	m := make(map[string]bool)
	for _, fm := range elasticMappings {
		m[fm.from] = true
	}
	return m
}()

var firewallKeys = func() map[string]bool {
	m := make(map[string]bool)
	for _, fm := range firewallMappings {
		m[fm.from] = true
	}
	return m
}()

type parseTestRequest struct {
	RawJSON string `json:"raw_json"`
}

type parseTestResponse struct {
	DetectedFormat string                 `json:"detected_format"`
	MappedFields   map[string]interface{} `json:"mapped_fields"`
	UnmappedFields []string               `json:"unmapped_fields"`
	Note           string                 `json:"note"`
}

func handleParseTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req parseTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.RawJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "raw_json is required"})
		return
	}

	// Parse the nested JSON
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(req.RawJSON), &raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "raw_json is not valid JSON"})
		return
	}

	// Flatten nested objects (for Elastic dot notation)
	flat := flattenMap(raw, "")

	// Detect format
	format := detectFormat(flat)

	// Apply mappings
	mapped := make(map[string]interface{})
	var unmapped []string

	for key, val := range flat {
		if fm, ok := allMappings[key]; ok {
			// Don't overwrite if already set (first wins)
			if _, exists := mapped[fm.to]; !exists {
				mapped[fm.to] = val
			}
		} else {
			unmapped = append(unmapped, key)
		}
	}

	// Severity normalization: numeric 1-10 to low/medium/high/critical
	if sev, ok := mapped["severity"]; ok {
		mapped["severity"] = normalizeSeverity(sev)
	}

	writeJSON(w, http.StatusOK, parseTestResponse{
		DetectedFormat: format,
		MappedFields:   mapped,
		UnmappedFields: unmapped,
		Note:           "Diagnostic preview \u2014 30 common mappings.",
	})
}

// flattenMap recursively flattens nested maps using dot notation.
func flattenMap(m map[string]interface{}, prefix string) map[string]interface{} {
	out := make(map[string]interface{})
	for k, v := range m {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		if nested, ok := v.(map[string]interface{}); ok {
			for nk, nv := range flattenMap(nested, fullKey) {
				out[nk] = nv
			}
		} else {
			out[fullKey] = v
		}
	}
	return out
}

// detectFormat checks which vendor's keys are present.
func detectFormat(flat map[string]interface{}) string {
	elasticHits := 0
	splunkHits := 0
	firewallHits := 0

	for key := range flat {
		if elasticKeys[key] {
			elasticHits++
		}
		if splunkKeys[key] {
			splunkHits++
		}
		if firewallKeys[key] {
			firewallHits++
		}
	}

	// Also detect by dot-notation patterns (Elastic nesting)
	for key := range flat {
		if strings.HasPrefix(key, "source.") || strings.HasPrefix(key, "destination.") ||
			strings.HasPrefix(key, "host.") || strings.HasPrefix(key, "user.") ||
			strings.HasPrefix(key, "event.") || strings.HasPrefix(key, "process.") ||
			strings.HasPrefix(key, "rule.") {
			elasticHits++
		}
	}

	if elasticHits > splunkHits && elasticHits > firewallHits {
		return "elastic"
	}
	if firewallHits > splunkHits {
		return "firewall"
	}
	if splunkHits > 0 {
		return "splunk"
	}
	return "unknown"
}

// normalizeSeverity converts numeric severity to string labels.
// 1-3 = low, 4-6 = medium, 7-9 = high, 10 = critical
func normalizeSeverity(val interface{}) interface{} {
	var num float64

	switch v := val.(type) {
	case float64:
		num = v
	case string:
		// If already a label, lowercase and return
		lower := strings.ToLower(v)
		if lower == "low" || lower == "medium" || lower == "high" || lower == "critical" {
			return lower
		}
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return val
		}
		num = parsed
	default:
		return val
	}

	n := int(num)
	switch {
	case n >= 10:
		return "critical"
	case n >= 7:
		return "high"
	case n >= 4:
		return "medium"
	case n >= 1:
		return "low"
	default:
		return val
	}
}
