package httputil

import (
	"context"
	"testing"
	"time"
)

func TestRetryDelay_Abort(t *testing.T) {
	d := RetryDelay(Abort, 0, 2*time.Second)
	if d != 0 {
		t.Errorf("Abort: got %v, want 0", d)
	}
}

func TestRetryDelay_Retry(t *testing.T) {
	base := 2 * time.Second
	for attempt := range 5 {
		d := RetryDelay(Retry, attempt, base)
		if d != base {
			t.Errorf("Retry attempt %d: got %v, want %v", attempt, d, base)
		}
	}
}

func TestRetryDelay_RateLimit_Progression(t *testing.T) {
	base := 2 * time.Second
	expected := []time.Duration{
		2 * time.Second,  // 2 << 0
		4 * time.Second,  // 2 << 1
		8 * time.Second,  // 2 << 2
		16 * time.Second, // 2 << 3
		30 * time.Second, // 2 << 4 = 32s, capped at 30s
		30 * time.Second, // shift capped at 4
	}

	for attempt, want := range expected {
		got := RetryDelay(RateLimit, attempt, base)
		if got != want {
			t.Errorf("RateLimit attempt %d: got %v, want %v", attempt, got, want)
		}
	}
}

func TestSleepContext_Normal(t *testing.T) {
	ctx := context.Background()
	ok := SleepContext(ctx, 10*time.Millisecond)
	if !ok {
		t.Error("SleepContext returned false for non-cancelled context")
	}
}

func TestSleepContext_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	ok := SleepContext(ctx, 10*time.Second)
	if ok {
		t.Error("SleepContext returned true for pre-cancelled context")
	}
}

func TestRetryDelay_Default(t *testing.T) {
	d := RetryDelay(ResponseAction(99), 0, 2*time.Second)
	if d != 0 {
		t.Errorf("Default: got %v, want 0", d)
	}
}
