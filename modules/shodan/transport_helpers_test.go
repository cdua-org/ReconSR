package shodan

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingReadCloser struct {
	readErr  error
	closeErr error
}

func (f failingReadCloser) Read(_ []byte) (int, error) {
	if f.readErr == nil {
		return 0, io.EOF
	}

	return 0, f.readErr
}

func (f failingReadCloser) Close() error {
	return f.closeErr
}

func withDefaultTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()

	original := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() {
		http.DefaultTransport = original
	})
}

func withShodanBaseURL(t *testing.T, value string) {
	t.Helper()

	original := shodanAPIBaseURL
	shodanAPIBaseURL = value
	t.Cleanup(func() {
		shodanAPIBaseURL = original
	})
}

func withInternetDBHostValue(t *testing.T, value string) {
	t.Helper()

	original := internetDBHost
	internetDBHost = value
	t.Cleanup(func() {
		internetDBHost = original
	})
}

func staticResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func okBodyResponse(body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       body,
	}
}

func markPreflightDone(module *shodanModule) {
	module.preflightOnce.Do(func() {})
}
