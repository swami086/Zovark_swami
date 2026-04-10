package main

import "testing"

func TestParseOTLPHostPort(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
		insecure bool
	}{
		{"http://zovark-signoz-collector:4318", "zovark-signoz-collector:4318", true},
		{"https://collector.example:4318", "collector.example:4318", false},
		{"host.docker.internal:4318", "host.docker.internal:4318", true},
		{"http://127.0.0.1:4318/v1/traces", "127.0.0.1:4318", true},
	}
	for _, tt := range tests {
		h, insec := parseOTLPHostPort(tt.raw)
		if h != tt.wantHost || insec != tt.insecure {
			t.Errorf("parseOTLPHostPort(%q) = (%q, %v), want (%q, %v)", tt.raw, h, insec, tt.wantHost, tt.insecure)
		}
	}
}
