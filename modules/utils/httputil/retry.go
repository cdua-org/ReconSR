package httputil

import (
	"context"
	"time"
)

const maxBackoff = 30 * time.Second

// SleepContext performs a context-aware sleep. Returns false if the context was cancelled early.
func SleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// RetryDelay computes the appropriate delay before the next retry attempt
// based on the classified ResponseAction and attempt number (0-based).
//
//   - Abort  → 0 (caller should not retry).
//   - Retry  → baseDelay (constant delay for transient server errors).
//   - RateLimit → baseDelay * 2^attempt, capped at 30 s (exponential backoff for 429).
func RetryDelay(action ResponseAction, attempt int, baseDelay time.Duration) time.Duration {
	switch action {
	case Abort:
		return 0
	case Retry:
		return baseDelay
	case RateLimit:
		shift := min(max(attempt, 0), 4)
		return min(baseDelay<<uint(shift), maxBackoff)
	default:
		return 0
	}
}
