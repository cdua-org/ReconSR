package debuglog

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	origStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = origStderr }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read pipe: %v", err)
	}
	return buf.String()
}

func TestPrintf_Enabled(t *testing.T) {
	resolver.Options["Debug"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")

	log := New("test")
	output := captureStderr(t, func() {
		log.Printf("hello %s %d", "world", 42)
	})

	expected := "[test-debug] hello world 42\n"
	if output != expected {
		t.Errorf("got %q, want %q", output, expected)
	}
}

func TestPrintf_Disabled_Unset(t *testing.T) {
	delete(resolver.Options, "Debug")

	log := New("test")
	output := captureStderr(t, func() {
		log.Printf("should not appear")
	})

	if output != "" {
		t.Errorf("expected no output when Debug is unset, got %q", output)
	}
}

func TestPrintf_Disabled_False(t *testing.T) {
	resolver.Options["Debug"] = strconv.FormatBool(false)
	defer delete(resolver.Options, "Debug")

	log := New("test")
	output := captureStderr(t, func() {
		log.Printf("should not appear")
	})

	if output != "" {
		t.Errorf("expected no output when Debug=false, got %q", output)
	}
}

func TestPrintf_CaseSensitive(t *testing.T) {
	for _, val := range []string{"True", "TRUE", "tRuE"} {
		resolver.Options["Debug"] = val
		log := New("case")
		output := captureStderr(t, func() {
			log.Printf("should not appear")
		})
		if output != "" {
			t.Errorf("Debug=%q: expected no output, got %q", val, output)
		}
	}
	delete(resolver.Options, "Debug")
}

func TestPrintf_Format(t *testing.T) {
	resolver.Options["Debug"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")

	log := New("dns")
	output := captureStderr(t, func() {
		log.Printf("target=%q qtype=%d", "example.com", 257)
	})

	if !strings.HasPrefix(output, "[dns-debug] ") {
		t.Errorf("expected prefix [dns-debug], got %q", output)
	}
	if !strings.HasSuffix(output, "\n") {
		t.Errorf("expected trailing newline, got %q", output)
	}
	if !strings.Contains(output, `target="example.com"`) {
		t.Errorf("expected formatted args in output, got %q", output)
	}
}
