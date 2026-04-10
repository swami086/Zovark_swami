package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func TestResolveCustomerID_HeaderPriority(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("X-Customer-ID", "cust-primary-01")
	r.Header.Set("X-Zovark-Customer-Id", "00000000-0000-0000-0000-000000000099")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = r
	if got := ResolveCustomerID(c); got != "cust-primary-01" {
		t.Fatalf("expected cust-primary-01, got %q", got)
	}
}

func TestResolveCustomerID_FallbackSystemTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = r
	if got := ResolveCustomerID(c); got != SystemTenantUUID {
		t.Fatalf("expected system tenant, got %q", got)
	}
}

func TestAllowIngestPerMinuteRedis_KeyAndLimit(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	ctx := context.Background()
	cid := "customer-test-01"

	for i := 0; i < 1000; i++ {
		ok, err := AllowIngestPerMinuteRedis(ctx, rdb, cid, IngestRatePerMinute)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	ok, err := AllowIngestPerMinuteRedis(ctx, rdb, cid, IngestRatePerMinute)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("1001st request should be denied")
	}
	keys := s.Keys()
	found := false
	for _, k := range keys {
		if strings.HasPrefix(k, "rate:ingest:") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected rate:ingest key, keys=%v", keys)
	}
}

func TestPlatformTrainingIngest_Unauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := PlatformTrainingIngest(PlatformIngestDeps{
		BearerSecret: "good",
		AllowIngest: func(ctx context.Context, customerID string) (bool, error) {
			return true, nil
		},
		Publish: func(ctx context.Context, customerID string, body []byte) error { return nil },
	})
	r := gin.New()
	r.POST("/ingest", h)
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader([]byte("parquet-bytes")))
	req.Header.Set("Authorization", "Bearer bad")
	req.Header.Set("X-Customer-ID", "customer-test-01")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", w.Code)
	}
}

func TestPlatformTrainingIngest_RateLimited(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := PlatformTrainingIngest(PlatformIngestDeps{
		BearerSecret: "sec",
		AllowIngest: func(ctx context.Context, customerID string) (bool, error) {
			return false, nil
		},
		Publish: func(ctx context.Context, customerID string, body []byte) error { return nil },
	})
	r := gin.New()
	r.POST("/ingest", h)
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader([]byte("x")))
	req.Header.Set("Authorization", "Bearer sec")
	req.Header.Set("X-Customer-ID", "customer-test-01")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 got %d", w.Code)
	}
}

func TestPlatformTrainingIngest_PublishError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := PlatformTrainingIngest(PlatformIngestDeps{
		BearerSecret: "sec",
		AllowIngest: func(ctx context.Context, customerID string) (bool, error) {
			return true, nil
		},
		Publish: func(ctx context.Context, customerID string, body []byte) error {
			return errors.New("kafka down")
		},
	})
	r := gin.New()
	r.POST("/ingest", h)
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader([]byte("parquet")))
	req.Header.Set("Authorization", "Bearer sec")
	req.Header.Set("X-Customer-ID", "customer-test-01")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 got %d", w.Code)
	}
}

func TestPlatformTrainingIngest_204(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var gotCustomer string
	var gotBody []byte
	h := PlatformTrainingIngest(PlatformIngestDeps{
		BearerSecret: "sec",
		AllowIngest: func(ctx context.Context, customerID string) (bool, error) {
			return true, nil
		},
		Publish: func(ctx context.Context, customerID string, body []byte) error {
			gotCustomer = customerID
			gotBody = append([]byte(nil), body...)
			return nil
		},
	})
	r := gin.New()
	r.POST("/ingest", h)
	payload := []byte{0x50, 0x41, 0x52, 0x31} // fake parquet magic
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer sec")
	req.Header.Set("X-Customer-ID", "customer-test-01")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204 got %d body=%s", w.Code, w.Body.String())
	}
	if gotCustomer != "customer-test-01" {
		t.Fatalf("customer: %q", gotCustomer)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body mismatch")
	}
}
