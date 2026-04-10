package main

import (
	"encoding/json"
	"testing"
)

func TestWebhookPathSentinelLikeOCSF(t *testing.T) {
	payload := map[string]interface{}{
		"properties": map[string]interface{}{
			"title":    "Suspicious sign-in",
			"severity": "high",
		},
		"entities": []interface{}{
			map[string]interface{}{
				"type": "ip",
				"properties": map[string]interface{}{
					"address": "203.0.113.50",
				},
			},
			map[string]interface{}{
				"type": "ip",
				"properties": map[string]interface{}{
					"address": "198.51.100.10",
				},
			},
		},
	}
	ocsf := ChooseSentinelOrGeneric(payload)
	if _, ok := ocsf["class_uid"]; !ok {
		t.Fatalf("expected class_uid: %#v", ocsf)
	}
	if endpointIPStr(ocsf, "src_endpoint") != "203.0.113.50" {
		t.Fatalf("src_endpoint: %#v", ocsf["src_endpoint"])
	}
	if endpointIPStr(ocsf, "dst_endpoint") != "198.51.100.10" {
		t.Fatalf("dst_endpoint: %#v", ocsf["dst_endpoint"])
	}
	an, sev, _, _, _ := OCSFSIEMColumnValues(ocsf)
	if an != "Suspicious sign-in" || sev != "high" {
		t.Fatalf("columns alert=%q sev=%q", an, sev)
	}
	h := computeOCSFCanonicalDedupHash(ocsf)
	if len(h) != 64 {
		t.Fatalf("dedup hash length: %d", len(h))
	}
}

func TestWebhookPathGenericWebhookOCSF(t *testing.T) {
	payload := map[string]interface{}{
		"alert_name": "Custom rule hit",
		"severity":   "medium",
		"source_ip":  "10.0.0.5",
		"dest_ip":    "10.0.0.6",
		"rule_name":  "CustomRule",
		"message":    "blocked connection",
	}
	ocsf := ChooseSentinelOrGeneric(payload)
	if ocsf["class_uid"].(int64) != ocsfSecurityFindingClassUID {
		t.Fatalf("class_uid: %v", ocsf["class_uid"])
	}
	if endpointIPStr(ocsf, "src_endpoint") != "10.0.0.5" {
		t.Fatalf("src: %#v", ocsf["src_endpoint"])
	}
	if endpointIPStr(ocsf, "dst_endpoint") != "10.0.0.6" {
		t.Fatalf("dst: %#v", ocsf["dst_endpoint"])
	}
	an, _, _, _, rn := OCSFSIEMColumnValues(ocsf)
	if an == "" || rn == "" {
		t.Fatalf("empty columns an=%q rn=%q", an, rn)
	}
	// Webhook stores exact body bytes; simulate round-trip
	body, _ := json.Marshal(payload)
	rawCopy := append([]byte(nil), body...)
	if !json.Valid(rawCopy) {
		t.Fatal("raw copy invalid JSON")
	}
	_ = rawCopy
}
