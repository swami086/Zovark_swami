package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// OCSF 1.3-oriented security finding objects produced at API ingest.
// Reference: https://schema.ocsf.io/ (Security Finding class_uid 2004, category Findings)

const (
	ocsfSchemaVersion           = "1.3.0"
	ocsfSecurityFindingClassUID = int64(2004)
	ocsfFindingsCategoryUID     = int64(2)
)

// --- Shared builders ---

func severityStringToID(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "5":
		return 5
	case "high", "4":
		return 4
	case "medium", "3":
		return 3
	case "low", "2":
		return 2
	case "informational", "info", "1":
		return 1
	default:
		return 3
	}
}

// cefSeverityToID maps ArcSight CEF severity (often 0–10) to OCSF severity_id.
func cefSeverityToID(s string) int {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		if n >= 9 {
			return 5
		}
		if n >= 7 {
			return 4
		}
		if n >= 5 {
			return 3
		}
		if n >= 3 {
			return 2
		}
		return 1
	}
	return severityStringToID(s)
}

func firstStringFromStringMap(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

func firstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case fmt.Stringer:
				return t.String()
			default:
				s := strings.TrimSpace(fmt.Sprintf("%v", v))
				if s != "" && s != "<nil>" {
					return s
				}
			}
		}
	}
	return ""
}

func nestedString(m map[string]interface{}, path ...string) string {
	cur := m
	for i, p := range path {
		if cur == nil {
			return ""
		}
		if i == len(path)-1 {
			if v, ok := cur[p].(string); ok {
				return v
			}
			return ""
		}
		next, ok := cur[p].(map[string]interface{})
		if !ok {
			return ""
		}
		cur = next
	}
	return ""
}

func endpointIP(ocsf map[string]interface{}, key string) string {
	if ocsf == nil {
		return ""
	}
	ep, ok := ocsf[key].(map[string]interface{})
	if !ok {
		return ""
	}
	if v, ok := ep["ip"].(string); ok {
		return v
	}
	return ""
}

// SourceIPFromTaskInput extracts source IP for API batching from legacy or OCSF-shaped siem_event.
func SourceIPFromTaskInput(input map[string]interface{}) string {
	if v, ok := input["source_ip"].(string); ok && v != "" {
		return v
	}
	se, ok := input["siem_event"].(map[string]interface{})
	if !ok {
		return ""
	}
	if v := endpointIP(se, "src_endpoint"); v != "" {
		return v
	}
	if v := firstString(se, "source_ip", "src_ip"); v != "" {
		return v
	}
	return ""
}

// DestIPFromTaskInput extracts destination IP for API batching.
func DestIPFromTaskInput(input map[string]interface{}) string {
	if v, ok := input["dest_ip"].(string); ok && v != "" {
		return v
	}
	se, ok := input["siem_event"].(map[string]interface{})
	if !ok {
		return ""
	}
	if v := endpointIP(se, "dst_endpoint"); v != "" {
		return v
	}
	if v := firstString(se, "destination_ip", "dest_ip", "dst_ip"); v != "" {
		return v
	}
	return ""
}

func buildSecurityFindingOCSF(ruleName, srcIP, dstIP, userName, message, severityStr, vendor string, vendorMeta map[string]interface{}) map[string]interface{} {
	sevStr := strings.ToLower(strings.TrimSpace(severityStr))
	if sevStr == "" {
		sevStr = "medium"
	}
	md := map[string]interface{}{
		"version": ocsfSchemaVersion,
		"product": map[string]interface{}{
			"name":        "Zovark API Ingest",
			"vendor_name": "Zovark",
		},
	}
	if vendor != "" {
		md["log_name"] = vendor
	}
	out := map[string]interface{}{
		"class_uid":    ocsfSecurityFindingClassUID,
		"category_uid": ocsfFindingsCategoryUID,
		"activity_id":  1,
		"severity_id":  severityStringToID(sevStr),
		"severity":     sevStr,
		"rule_name":    ruleName,
		"finding_info": map[string]interface{}{
			"title": ruleName,
		},
		"metadata": md,
	}
	if srcIP != "" {
		out["src_endpoint"] = map[string]interface{}{"ip": srcIP}
	}
	if dstIP != "" {
		out["dst_endpoint"] = map[string]interface{}{"ip": dstIP}
	}
	if userName != "" {
		out["actor"] = map[string]interface{}{
			"user": map[string]interface{}{"name": userName},
		}
	}
	if message != "" {
		out["message"] = message
	}
	if len(vendorMeta) > 0 {
		out["unmapped"] = vendorMeta
	}
	return out
}

// NormalizeSplunkHEC maps Splunk HEC JSON event + envelope fields to OCSF.
func NormalizeSplunkHEC(event map[string]interface{}, sourceType, host, source string) map[string]interface{} {
	rule := firstString(event, "signature", "alert_name", "name", "search_name", "ss_name")
	if rule == "" {
		rule = sourceType
	}
	srcIP := firstString(event, "src_ip", "source_ip", "src")
	dstIP := firstString(event, "dest_ip", "destination_ip", "dst")
	user := firstString(event, "user", "username", "src_user", "account_name")
	msg := firstString(event, "raw", "_raw", "message", "msg")
	sev := firstString(event, "severity")
	if sev == "" {
		sev = "medium"
	}
	meta := map[string]interface{}{}
	if host != "" {
		meta["splunk_host"] = host
	}
	if sourceType != "" {
		meta["splunk_sourcetype"] = sourceType
	}
	if source != "" {
		meta["splunk_source"] = source
	}
	return buildSecurityFindingOCSF(rule, srcIP, dstIP, user, msg, sev, "splunk_hec", meta)
}

// NormalizeElasticECS maps Elastic Security / ECS-style alert JSON to OCSF.
func NormalizeElasticECS(payload map[string]interface{}) map[string]interface{} {
	ruleName := ""
	ruleDesc := ""
	sev := "medium"
	if ruleObj, ok := payload["rule"].(map[string]interface{}); ok {
		ruleName = firstString(ruleObj, "name")
		ruleDesc = firstString(ruleObj, "description")
		sev = firstString(ruleObj, "severity")
		if sev == "" {
			sev = "medium"
		}
	}
	srcIP := nestedString(payload, "source", "ip")
	if srcIP == "" {
		srcIP = nestedString(payload, "source", "address")
	}
	dstIP := nestedString(payload, "destination", "ip")
	if dstIP == "" {
		dstIP = nestedString(payload, "destination", "address")
	}
	user := nestedString(payload, "user", "name")
	msg := firstString(payload, "message")
	meta := map[string]interface{}{"elastic_payload": true}
	if ruleDesc != "" {
		meta["rule_description"] = ruleDesc
	}
	return buildSecurityFindingOCSF(ruleName, srcIP, dstIP, user, msg, sev, "elastic_siem", meta)
}

// NormalizeFlatSIEMToOCSF maps flat ZCS-style maps (e.g. from siem_alerts) to OCSF.
func NormalizeFlatSIEMToOCSF(flat map[string]interface{}) map[string]interface{} {
	rule := firstString(flat, "rule_name", "alert_name")
	src := firstString(flat, "source_ip", "src_ip")
	dst := firstString(flat, "dest_ip", "destination_ip", "dst_ip")
	user := firstString(flat, "username", "user")
	msg := firstString(flat, "raw_log", "message")
	sev := firstString(flat, "severity")
	if sev == "" {
		sev = "medium"
	}
	return buildSecurityFindingOCSF(rule, src, dst, user, msg, sev, "siem_alert", nil)
}

// NormalizeGenericWebhook maps arbitrary JSON webhook bodies to OCSF (best-effort).
func NormalizeGenericWebhook(payload map[string]interface{}) map[string]interface{} {
	if payload == nil {
		return buildSecurityFindingOCSF("webhook_alert", "", "", "", "", "medium", "generic_webhook", nil)
	}
	// Nested alert shapes
	for _, key := range []string{"alert", "detection", "incident", "event"} {
		if inner, ok := payload[key].(map[string]interface{}); ok {
			return NormalizeGenericWebhook(inner)
		}
	}
	rule := firstString(payload, "rule_name", "title", "name", "alert_name", "signature")
	src := firstString(payload, "source_ip", "src_ip", "src")
	dst := firstString(payload, "destination_ip", "dest_ip", "dst_ip", "dst")
	user := firstString(payload, "username", "user", "user_name")
	msg := firstString(payload, "message", "raw_log", "description", "msg")
	sev := firstString(payload, "severity")
	if sev == "" {
		sev = "medium"
	}
	if rule == "" {
		rule = "webhook_alert"
	}
	return buildSecurityFindingOCSF(rule, src, dst, user, msg, sev, "generic_webhook", map[string]interface{}{"original_keys": keysSample(payload, 20)})
}

func keysSample(m map[string]interface{}, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
		if len(out) >= max {
			break
		}
	}
	return out
}

// NormalizeMicrosoftSentinel maps common Sentinel incident / alert JSON to OCSF (best-effort).
func NormalizeMicrosoftSentinel(payload map[string]interface{}) map[string]interface{} {
	title := ""
	sev := "medium"
	if props, ok := payload["properties"].(map[string]interface{}); ok {
		title = firstString(props, "title", "alertDisplayName")
		sev = firstString(props, "severity")
	}
	if title == "" {
		title = firstString(payload, "title", "name")
	}
	// Entities: try to pull IPs from first few entities
	srcIP, dstIP := "", ""
	if ents, ok := payload["entities"].([]interface{}); ok {
		for _, e := range ents {
			em, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			if t, _ := em["type"].(string); strings.EqualFold(t, "ip") {
				if a, ok := em["properties"].(map[string]interface{}); ok {
					ip := firstString(a, "address", "ipAddress")
					if ip != "" && srcIP == "" {
						srcIP = ip
					} else if ip != "" && dstIP == "" {
						dstIP = ip
					}
				}
			}
		}
	}
	msg := firstString(payload, "description")
	if msg == "" {
		b, _ := json.Marshal(payload)
		if len(b) > 8000 {
			msg = string(b[:8000])
		} else {
			msg = string(b)
		}
	}
	return buildSecurityFindingOCSF(title, srcIP, dstIP, "", msg, sev, "microsoft_sentinel", nil)
}

// ParseCEF parses a single CEF line (ArcSight) into OCSF.
func ParseCEF(line string) (map[string]interface{}, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "CEF:") {
		return nil, fmt.Errorf("not a CEF line")
	}
	rest := line[4:]
	parts := strings.SplitN(rest, "|", 8)
	if len(parts) < 8 {
		return nil, fmt.Errorf("CEF: expected at least 8 pipe-separated fields")
	}
	// parts[0]=version,1=vendor,2=product,3=version,4=signature id,5=name,6=severity,7=extension
	name := parts[5]
	sev := parts[6]
	ext := parts[7]
	kv := parseCEFExtensions(ext)
	srcIP := kv["src"]
	if srcIP == "" {
		srcIP = kv["shost"]
	}
	dstIP := kv["dst"]
	if dstIP == "" {
		dstIP = kv["dhost"]
	}
	user := kv["suser"]
	if user == "" {
		user = kv["duser"]
	}
	msg := kv["msg"]
	if msg == "" {
		msg = kv["request"]
	}
	meta := map[string]interface{}{
		"cef_device_vendor":    parts[1],
		"cef_device_product":   parts[2],
		"cef_device_version":   parts[3],
		"cef_signature_id":     parts[4],
		"cef_extension_keys":   keysSample(stringMapToIface(kv), 15),
		"cef_raw_extensions":   ext,
	}
	ocsf := buildSecurityFindingOCSF(name, srcIP, dstIP, user, msg, sev, "arcsight_cef", meta)
	ocsf["severity_id"] = cefSeverityToID(sev)
	return ocsf, nil
}

func parseCEFExtensions(ext string) map[string]string {
	out := map[string]string{}
	ext = strings.TrimSpace(ext)
	if ext == "" {
		return out
	}
	for _, tok := range strings.Fields(ext) {
		i := strings.Index(tok, "=")
		if i <= 0 || i >= len(tok)-1 {
			continue
		}
		k := tok[:i]
		v := tok[i+1:]
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// leefPairSeparatorFromDelimiterField maps QRadar delimiter token to the separator between key=value pairs.
func leefPairSeparatorFromDelimiterField(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return "\t"
	}
	if d == `\t` || strings.EqualFold(d, "tab") {
		return "\t"
	}
	if len(d) == 1 {
		return d
	}
	return "\t"
}

// parseLEEFAttributePairs splits attribute payload into key=value pairs using pairSep between pairs.
func parseLEEFAttributePairs(s, pairSep string) map[string]string {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	var segments []string
	switch {
	case pairSep == "\t":
		segments = strings.Split(s, "\t")
	case pairSep != "":
		segments = strings.Split(s, pairSep)
	default:
		segments = strings.Split(s, "\t")
	}
	for _, p := range segments {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		i := strings.Index(p, "=")
		if i <= 0 || i >= len(p)-1 {
			continue
		}
		k := strings.TrimSpace(p[:i])
		v := strings.TrimSpace(p[i+1:])
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// ParseLEEF parses a single LEEF line (QRadar) into OCSF.
// Supports: (a) LEEF:Ver|Vendor|Product|DevVer|EventID|k=v<tab>... with default tab pairs,
// and (b) LEEF:...|EventID|<delimiter>|k=v<delim>... when an explicit delimiter field is present.
func ParseLEEF(line string) (map[string]interface{}, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "LEEF:") {
		return nil, fmt.Errorf("not a LEEF line")
	}
	rest := line[5:]
	parts := strings.Split(rest, "|")
	if len(parts) < 6 {
		return nil, fmt.Errorf("LEEF: expected at least Version|Vendor|Product|Version|EventID|attributes")
	}
	leefSpecVer, vendor, product, devVer, eventID := parts[0], parts[1], parts[2], parts[3], parts[4]
	var kv map[string]string
	if len(parts) == 6 {
		kv = parseLEEFAttributePairs(parts[5], "\t")
	} else {
		pairSep := leefPairSeparatorFromDelimiterField(parts[5])
		attrSection := strings.Join(parts[6:], "|")
		kv = parseLEEFAttributePairs(attrSection, pairSep)
	}
	name := firstStringFromStringMap(kv, "cat", "name", "type")
	if name == "" {
		name = eventID
	}
	srcIP := firstStringFromStringMap(kv, "src", "sourceIP", "source_address")
	dstIP := firstStringFromStringMap(kv, "dst", "destIP", "destination_address")
	user := firstStringFromStringMap(kv, "usrName", "user", "username")
	msg := firstStringFromStringMap(kv, "msg", "message", "url")
	sev := firstStringFromStringMap(kv, "sev", "Severity", "severity")
	if sev == "" {
		sev = "medium"
	}
	meta := map[string]interface{}{
		"leef_spec_version": leefSpecVer,
		"leef_vendor":       vendor,
		"leef_product":      product,
		"leef_version":      devVer,
		"leef_event_id":     eventID,
		"leef_attr_keys":    keysSample(stringMapToIface(kv), 20),
	}
	ocsf := buildSecurityFindingOCSF(name, srcIP, dstIP, user, msg, sev, "qradar_leef", meta)
	return ocsf, nil
}

func stringMapToIface(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}


// OCSFSIEMColumnValues extracts flat column values for siem_alerts from an OCSF map.
func OCSFSIEMColumnValues(ocsf map[string]interface{}) (alertName, severity, sourceIP, destIP, ruleName string) {
	severity = "medium"
	if s, ok := ocsf["severity"].(string); ok && s != "" {
		severity = s
	}
	if ep, ok := ocsf["src_endpoint"].(map[string]interface{}); ok {
		if ip, ok := ep["ip"].(string); ok {
			sourceIP = ip
		}
	}
	if ep, ok := ocsf["dst_endpoint"].(map[string]interface{}); ok {
		if ip, ok := ep["ip"].(string); ok {
			destIP = ip
		}
	}
	if fi, ok := ocsf["finding_info"].(map[string]interface{}); ok {
		if t, ok := fi["title"].(string); ok && t != "" {
			alertName = t
		}
	}
	if r, ok := ocsf["rule_name"].(string); ok && r != "" {
		ruleName = r
	}
	if alertName == "" {
		alertName = ruleName
	}
	if alertName == "" {
		alertName = "Unknown Alert"
	}
	if ruleName == "" {
		ruleName = alertName
	}
	return
}

// ChooseSentinelOrGeneric detects Sentinel-shaped JSON and normalizes accordingly.
func ChooseSentinelOrGeneric(payload map[string]interface{}) map[string]interface{} {
	if payload == nil {
		return NormalizeGenericWebhook(nil)
	}
	if _, ok := payload["properties"]; ok {
		if _, ok2 := payload["entities"]; ok2 {
			return NormalizeMicrosoftSentinel(payload)
		}
	}
	if strings.Contains(strings.ToLower(fmt.Sprintf("%v", payload["type"])), "microsoft.security") {
		return NormalizeMicrosoftSentinel(payload)
	}
	return NormalizeGenericWebhook(payload)
}
