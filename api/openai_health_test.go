package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckOpenAIReachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	chatURL := ts.URL + "/v1/chat/completions"
	if !checkOpenAIReachable(chatURL, "secret") {
		t.Fatal("expected reachable with valid key")
	}
	if checkOpenAIReachable(chatURL, "wrong") {
		t.Fatal("expected unreachable with bad key")
	}
}
