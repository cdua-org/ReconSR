package debuglog

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"cdua-org/ReconSR/modules/utils/resolver"
)

const testDebugLogFile = "debug.log"

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

func resetDebugLogState(t *testing.T) {
	t.Helper()

	t.Chdir(t.TempDir())

	if debugLogFile != nil {
		if err := debugLogFile.Close(); err != nil {
			t.Fatalf("failed to close debug log file: %v", err)
		}
	}

	debugLogFile = nil
	errDebugLog = nil
	debugLogOnce = sync.Once{}
	writeMu = sync.Mutex{}
	debugLogPath = testDebugLogFile
}

func TestPrintf_Enabled(t *testing.T) {
	resetDebugLogState(t)
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

	fileOutput, err := os.ReadFile(testDebugLogFile)
	if err != nil {
		t.Fatalf("failed to read debug log file: %v", err)
	}
	if string(fileOutput) != expected {
		t.Errorf("file got %q, want %q", string(fileOutput), expected)
	}
}

func TestPrintf_Disabled_Unset(t *testing.T) {
	resetDebugLogState(t)
	delete(resolver.Options, "Debug")

	log := New("test")
	output := captureStderr(t, func() {
		log.Printf("should not appear")
	})

	if output != "" {
		t.Errorf("expected no output when Debug is unset, got %q", output)
	}
	if _, err := os.Stat(testDebugLogFile); !os.IsNotExist(err) {
		t.Errorf("expected no debug log file when Debug is unset, got err=%v", err)
	}
}

func TestPrintf_Disabled_False(t *testing.T) {
	resetDebugLogState(t)
	resolver.Options["Debug"] = strconv.FormatBool(false)
	defer delete(resolver.Options, "Debug")

	log := New("test")
	output := captureStderr(t, func() {
		log.Printf("should not appear")
	})

	if output != "" {
		t.Errorf("expected no output when Debug=false, got %q", output)
	}
	if _, err := os.Stat(testDebugLogFile); !os.IsNotExist(err) {
		t.Errorf("expected no debug log file when Debug=false, got err=%v", err)
	}
}

func TestPrintf_CaseSensitive(t *testing.T) {
	resetDebugLogState(t)

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
	resetDebugLogState(t)
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

	fileOutput, err := os.ReadFile(testDebugLogFile)
	if err != nil {
		t.Fatalf("failed to read debug log file: %v", err)
	}
	if string(fileOutput) != output {
		t.Errorf("expected file output %q, got %q", output, string(fileOutput))
	}
}

func TestPrintf_TruncatesExistingLogOnFirstWrite(t *testing.T) {
	resetDebugLogState(t)
	resolver.Options["Debug"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")

	if err := os.WriteFile(testDebugLogFile, []byte("old data\n"), 0o600); err != nil {
		t.Fatalf("failed to seed debug log file: %v", err)
	}

	log := New("fresh")
	output := captureStderr(t, func() {
		log.Printf("new data")
	})

	fileOutput, err := os.ReadFile(testDebugLogFile)
	if err != nil {
		t.Fatalf("failed to read debug log file: %v", err)
	}
	if string(fileOutput) != output {
		t.Errorf("expected file output %q, got %q", output, string(fileOutput))
	}
}
