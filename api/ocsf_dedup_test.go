package main

import (
	"encoding/json"
	"testing"
)

func TestCrossVendorDedupHashSplunkVsElastic(t *testing.T) {
	splunkEvent := map[string]interface{}{
		"signature":       "Brute Force Login",
		"src_ip":          "192.0.2.10",
		"dest_ip":         "192.0.2.20",
		"user":            "alice",
		"raw":             "failed auth",
		"severity":        "high",
	}
	ocsfSplunk := NormalizeSplunkHEC(splunkEvent, "linux:secure", "host-a", "syslog")

	elasticPayload := map[string]interface{}{
		"rule": map[string]interface{}{
			"name":     "Brute Force Login",
			"severity": "high",
		},
		"source":      map[string]interface{}{"ip": "192.0.2.10"},
		"destination": map[string]interface{}{"ip": "192.0.2.20"},
		"user":        map[string]interface{}{"name": "alice"},
		"message":     "failed auth",
	}
	ocsfElastic := NormalizeElasticECS(elasticPayload)

	h1 := computeOCSFCanonicalDedupHash(ocsfSplunk)
	h2 := computeOCSFCanonicalDedupHash(ocsfElastic)
	if h1 != h2 {
		t.Fatalf("dedup mismatch: splunk=%s elastic=%s\nsplunk_json=%s\nelastic_json=%s",
			h1, h2, mustJSON(ocsfSplunk), mustJSON(ocsfElastic))
	}
}

func TestParseCEFProducesOCSF(t *testing.T) {
	line := `CEF:0|TestVendor|TestProduct|1.0|100|SSH Brute|10|src=192.0.2.1 dst=192.0.2.2 suser=root msg=attempt`
	ev, err := ParseCEF(line)
	if err != nil {
		t.Fatal(err)
	}
	if ev["class_uid"].(int64) != ocsfSecurityFindingClassUID {
		t.Fatalf("class_uid: %v", ev["class_uid"])
	}
	if endpointIPStr(ev, "src_endpoint") != "192.0.2.1" {
		t.Fatalf("src ip: %v", ev["src_endpoint"])
	}
}

func TestParseLEEFProducesOCSF(t *testing.T) {
	line := "LEEF:2.0|QRadar|Sim|1.0|12345|src=10.0.0.1\tdst=10.0.0.2\tusrName=bob\tsev=5"
	ev, err := ParseLEEF(line)
	if err != nil {
		t.Fatal(err)
	}
	if endpointIPStr(ev, "src_endpoint") != "10.0.0.1" {
		t.Fatalf("src: %#v", ev["src_endpoint"])
	}
	if endpointIPStr(ev, "dst_endpoint") != "10.0.0.2" {
		t.Fatalf("dst: %#v", ev["dst_endpoint"])
	}
	act := ocsfActorUserName(ev)
	if act != "bob" {
		t.Fatalf("actor.user.name: got %q", act)
	}
	if ev["severity"].(string) != "5" {
		t.Fatalf("severity: %v", ev["severity"])
	}
}

// Explicit delimiter field (QRadar): parts[5] is delimiter token, attributes follow in parts[6+].
func TestParseLEEFWithExplicitDelimiterTabToken(t *testing.T) {
	line := "LEEF:2.0|QRadar|Sim|1.0|12345|\\t|src=10.1.1.1\tdst=10.2.2.2\tusrName=alice\tsev=high"
	ev, err := ParseLEEF(line)
	if err != nil {
		t.Fatal(err)
	}
	if endpointIPStr(ev, "src_endpoint") != "10.1.1.1" {
		t.Fatalf("src: %#v", ev["src_endpoint"])
	}
	if endpointIPStr(ev, "dst_endpoint") != "10.2.2.2" {
		t.Fatalf("dst: %#v", ev["dst_endpoint"])
	}
	if ocsfActorUserName(ev) != "alice" {
		t.Fatalf("user: %v", ocsfActorUserName(ev))
	}
	if ev["severity"].(string) != "high" {
		t.Fatalf("severity: %v", ev["severity"])
	}
}

func TestParseLEEFWithExplicitDelimiterSemicolon(t *testing.T) {
	line := "LEEF:1.0|V|P|1|eid|;|src=1.1.1.1;dst=2.2.2.2;usrName=carol;sev=4"
	ev, err := ParseLEEF(line)
	if err != nil {
		t.Fatal(err)
	}
	if endpointIPStr(ev, "src_endpoint") != "1.1.1.1" || endpointIPStr(ev, "dst_endpoint") != "2.2.2.2" {
		t.Fatalf("endpoints src=%q dst=%q", endpointIPStr(ev, "src_endpoint"), endpointIPStr(ev, "dst_endpoint"))
	}
	if ocsfActorUserName(ev) != "carol" {
		t.Fatalf("user: %q", ocsfActorUserName(ev))
	}
	if ev["severity"].(string) != "4" {
		t.Fatalf("severity: %v", ev["severity"])
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
