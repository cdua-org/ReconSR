package shodan

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWaitRateLimit(t *testing.T) {
	module := &shodanModule{}
	module.lastReqTime = time.Now()

	start := time.Now()
	module.waitRateLimit()
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("waitRateLimit should sleep for about 1100ms, slept for %v", elapsed)
	}

	start = time.Now()
	module.waitRateLimit()
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("second waitRateLimit should sleep for about 1100ms, slept for %v", elapsed)
	}
}

func TestHandlePreflightAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "invalid" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"query_credits":42}`)); err != nil {
			t.Fatalf("write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := shodanAPIBaseURL
	shodanAPIBaseURL = server.URL
	defer func() { shodanAPIBaseURL = originalBaseURL }()

	invalidModule := &shodanModule{apiKey: "invalid"}
	invalidModule.lastReqTime = time.Now().Add(-2 * time.Second)
	invalidModule.handlePreflightAPI()
	if !invalidModule.keyInvalid {
		t.Fatal("expected invalid key to be marked as invalid")
	}

	validModule := &shodanModule{apiKey: "valid"}
	validModule.lastReqTime = time.Now().Add(-2 * time.Second)
	validModule.handlePreflightAPI()
	if validModule.keyInvalid {
		t.Fatal("expected valid key to stay valid")
	}
	if validModule.queryCredits != 42 {
		t.Fatalf("expected 42 credits, got %d", validModule.queryCredits)
	}
}
