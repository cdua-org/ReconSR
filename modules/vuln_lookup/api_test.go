package vuln_lookup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestEnforceDelay_ContextCanceled(t *testing.T) {
	origDelay := resolver.CirclMutexDelayMs
	resolver.CirclMutexDelayMs = 1000
	defer func() { resolver.CirclMutexDelayMs = origDelay }()

	m := &module{lastReqTime: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.enforceDelay(ctx)
	if err == nil || err.Error() == "" {
		t.Errorf("expected error due to canceled context")
	}
}

func TestEnforceDelay_Success(t *testing.T) {
	origDelay := resolver.CirclMutexDelayMs
	defer func() { resolver.CirclMutexDelayMs = origDelay }()

	m := &module{}

	resolver.CirclMutexDelayMs = 0
	if err := m.enforceDelay(context.Background()); err != nil {
		t.Errorf("expected no error when delay is 0, got %v", err)
	}

	resolver.CirclMutexDelayMs = 10
	m.lastReqTime = time.Now().Add(-1 * time.Second)
	if err := m.enforceDelay(context.Background()); err != nil {
		t.Errorf("expected no error when delay has passed, got %v", err)
	}

	resolver.CirclMutexDelayMs = 10
	m.lastReqTime = time.Now()
	if err := m.enforceDelay(context.Background()); err != nil {
		t.Errorf("expected no error after waiting, got %v", err)
	}
}

func TestFetchCircl_Errors(t *testing.T) {
	origRetries := resolver.MaxRetriesCircl
	resolver.MaxRetriesCircl = 2
	defer func() { resolver.MaxRetriesCircl = origRetries }()

	origBaseDelay := resolver.CirclRetryBaseDelay
	resolver.CirclRetryBaseDelay = time.Millisecond
	defer func() { resolver.CirclRetryBaseDelay = origBaseDelay }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := &module{}
	_, err := m.fetchCircl(context.Background(), srv.URL, "test", "target")
	if err == nil {
		t.Errorf("expected error max retries exceeded")
	}

	_, err = m.fetchCircl(context.Background(), "http://127.0.0.1:0", "test", "target")
	if err == nil {
		t.Errorf("expected do request error")
	}
}

func TestFetchCircl_NewRequestError(t *testing.T) {
	m := &module{}
	_, err := m.fetchCircl(context.Background(), "http://127.0.0.1:\x00", "test", "target")
	if err == nil {
		t.Errorf("expected error from create request")
	}
}

func TestFetchCircl_EnforceDelayError(t *testing.T) {
	origDelay := resolver.CirclMutexDelayMs
	resolver.CirclMutexDelayMs = 1000
	defer func() { resolver.CirclMutexDelayMs = origDelay }()

	m := &module{lastReqTime: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := m.fetchCircl(ctx, "http://127.0.0.1", "test", "target")
	if err == nil {
		t.Errorf("expected enforceDelay error")
	}
}

func TestFetchCircl_WithAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &module{apiKey: "test_secret"}
	_, err := m.fetchCircl(context.Background(), srv.URL, "test", "target")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProcessCirclResponse_UnexpectedStatus(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusTeapot}
	retry, err := processCirclResponse(context.Background(), resp, 1, "http://test", "test_func", "test_target")
	if retry {
		t.Errorf("expected no retry")
	}
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestProcessCirclResponse_Paths(t *testing.T) {
	resp400 := &http.Response{StatusCode: http.StatusBadRequest}
	retry, err := processCirclResponse(context.Background(), resp400, 1, "url", "func", "target")
	if retry || err == nil {
		t.Errorf("expected no retry and error for 400, got retry=%v, err=%v", retry, err)
	}

	ctxCanceled, cancel := context.WithCancel(context.Background())
	cancel()

	resp429 := &http.Response{StatusCode: http.StatusTooManyRequests, Header: make(http.Header)}
	retry, err = processCirclResponse(ctxCanceled, resp429, 1, "url", "func", "target")
	if retry || err == nil {
		t.Errorf("expected no retry due to context cancel on 429, got retry=%v, err=%v", retry, err)
	}

	resp500 := &http.Response{StatusCode: http.StatusInternalServerError}
	retry, err = processCirclResponse(ctxCanceled, resp500, 1, "url", "func", "target")
	if retry || err == nil {
		t.Errorf("expected no retry due to context cancel on 500, got retry=%v, err=%v", retry, err)
	}
}

func TestProcessCirclResponse_SleepSuccess(t *testing.T) {
	origDelay := resolver.CirclRetryBaseDelay
	resolver.CirclRetryBaseDelay = time.Millisecond
	defer func() { resolver.CirclRetryBaseDelay = origDelay }()

	resp429 := &http.Response{StatusCode: http.StatusTooManyRequests, Header: make(http.Header)}
	retry, err := processCirclResponse(context.Background(), resp429, 1, "url", "func", "target")
	if !retry || err == nil {
		t.Errorf("expected retry and error for 429, got retry=%v, err=%v", retry, err)
	}

	resp500 := &http.Response{StatusCode: http.StatusInternalServerError}
	retry, err = processCirclResponse(context.Background(), resp500, 1, "url", "func", "target")
	if !retry || err == nil {
		t.Errorf("expected retry and error for 500, got retry=%v, err=%v", retry, err)
	}
}

func TestParseRateLimitDelay(t *testing.T) {
	fallback := time.Second

	resp1 := &http.Response{Header: make(http.Header)}
	resp1.Header.Set("Retry-After", "2")
	delay1, src1 := parseRateLimitDelay(resp1, fallback)
	if src1 != "retry_after" || delay1 != 3*time.Second {
		t.Errorf("expected 3s and retry_after, got %v %s", delay1, src1)
	}

	resp2 := &http.Response{Header: make(http.Header)}
	future := time.Now().Add(2 * time.Second).Unix()
	resp2.Header.Set("X-RateLimit-Reset", strconv.FormatInt(future, 10))
	delay2, src2 := parseRateLimitDelay(resp2, fallback)
	if src2 != "ratelimit_reset" || delay2 <= 0 {
		t.Errorf("expected ratelimit_reset and positive delay, got %v %s", delay2, src2)
	}
}

func TestParseRateLimitDelay_GarbageAndPast(t *testing.T) {
	fallback := time.Second

	resp1 := &http.Response{Header: make(http.Header)}
	resp1.Header.Set("Retry-After", "abc")
	delay1, _ := parseRateLimitDelay(resp1, fallback)
	if delay1 != fallback {
		t.Errorf("expected fallback for garbage Retry-After, got %v", delay1)
	}

	resp2 := &http.Response{Header: make(http.Header)}
	resp2.Header.Set("X-RateLimit-Reset", "abc")
	delay2, _ := parseRateLimitDelay(resp2, fallback)
	if delay2 != fallback {
		t.Errorf("expected fallback for garbage X-RateLimit-Reset, got %v", delay2)
	}

	resp3 := &http.Response{Header: make(http.Header)}
	past := time.Now().Add(-1 * time.Second).Unix()
	resp3.Header.Set("X-RateLimit-Reset", strconv.FormatInt(past, 10))
	delay3, _ := parseRateLimitDelay(resp3, fallback)
	if delay3 != fallback {
		t.Errorf("expected fallback for past X-RateLimit-Reset, got %v", delay3)
	}
}

func TestFetchCircl_ReadAllError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		if _, err := w.Write([]byte("short")); err != nil {
			t.Logf("write error: %v", err)
		}
	}))
	defer srv.Close()

	m := &module{}
	_, err := m.fetchCircl(context.Background(), srv.URL, "test", "target")
	if err == nil {
		t.Errorf("expected read body error")
	}
}

func TestFetchCircl_AbortError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	m := &module{}
	_, err := m.fetchCircl(context.Background(), srv.URL, "test", "target")
	if err == nil {
		t.Errorf("expected abort error")
	}
}
