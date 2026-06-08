package shodan

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSanitizeShodanLogValue(t *testing.T) {
	sanitized := sanitizeShodanLogValue("https://api.shodan.io/dns/domain/example.com?key=super-secret&page=2")
	if strings.Contains(sanitized, "super-secret") {
		t.Fatalf("expected key to be redacted, got %q", sanitized)
	}
	if !strings.Contains(sanitized, "key=[redacted]") {
		t.Fatalf("expected redacted marker in sanitized url, got %q", sanitized)
	}
	if !strings.Contains(sanitized, "page=2") {
		t.Fatalf("expected non-secret query params to be preserved, got %q", sanitized)
	}
}

func TestSanitizeShodanError(t *testing.T) {
	err := errors.New("Get \"https://api.shodan.io/api-info?key=super-secret&history=true\": EOF")
	sanitized := sanitizeShodanError(err)
	if sanitized == nil {
		t.Fatal("expected sanitized error")
	}
	if strings.Contains(sanitized.Error(), "super-secret") {
		t.Fatalf("expected key to be redacted, got %q", sanitized.Error())
	}
	if !strings.Contains(sanitized.Error(), "key=[redacted]") {
		t.Fatalf("expected redacted marker in sanitized error, got %q", sanitized.Error())
	}
	if !strings.Contains(sanitized.Error(), "history=true") {
		t.Fatalf("expected non-secret query params to be preserved, got %q", sanitized.Error())
	}
}

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
