// Package httputil provides HTTP response classification and retry
// helpers shared across all ReconSR modules that interact with
// external HTTP APIs.
package httputil

// ResponseAction indicates how the caller should react to an HTTP status code.
type ResponseAction int

const (
	// Retry indicates a transient server error (5xx, 408); standard retry with base delay.
	Retry ResponseAction = iota
	// RateLimit indicates HTTP 429; retry with exponential backoff.
	RateLimit
	// Abort indicates a permanent client error (4xx except 408/429); do not retry.
	Abort
)

// ClassifyStatus maps an HTTP status code to the appropriate ResponseAction.
func ClassifyStatus(statusCode int) ResponseAction {
	switch {
	case statusCode == 408:
		return Retry
	case statusCode == 429:
		return RateLimit
	case statusCode >= 520 && statusCode <= 530:
		// Cloudflare-specific CDN/proxy errors — typically transient.
		return Retry
	case statusCode >= 400 && statusCode < 500:
		return Abort
	case statusCode >= 500:
		return Retry
	default:
		// 1xx, 2xx, 3xx — caller should not classify successful/redirect responses,
		// but return Abort as a safe default (no retry for non-error codes).
		return Abort
	}
}
