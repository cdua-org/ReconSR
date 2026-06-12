package vuln_lookup

import (
	"context"
	"net/http"
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
