package debuglog

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

const testDebugLogFile = "debug.log"

type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

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
	timeNow = time.Now
}

func withFixedTime(t *testing.T, ts time.Time) {
	t.Helper()
	oldTimeNow := timeNow
	timeNow = func() time.Time { return ts }
	t.Cleanup(func() {
		timeNow = oldTimeNow
	})
}

func TestPrintf_Enabled(t *testing.T) {
	resetDebugLogState(t)
	withFixedTime(t, time.Date(2026, time.June, 7, 14, 23, 11, 482000000, time.FixedZone("MSK", 3*60*60)))
	resolver.Options["Debug"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")
	delete(resolver.Options, "DebugConsole")

	log := New("test")
	output := captureStderr(t, func() {
		log.Printf("hello %s %d", "world", 42)
	})

	expected := "[2026-06-07T14:23:11.482+03:00] [test-debug] hello world 42\n"
	if output != "" {
		t.Errorf("expected no console output when DebugConsole is unset, got %q", output)
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

func TestPrintf_ConsoleDisabledWhenDebugFalse(t *testing.T) {
	resetDebugLogState(t)
	resolver.Options["Debug"] = strconv.FormatBool(false)
	resolver.Options["DebugConsole"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")
	defer delete(resolver.Options, "DebugConsole")

	log := New("test")
	output := captureStderr(t, func() {
		log.Printf("should not appear")
	})

	if output != "" {
		t.Errorf("expected no console output when Debug=false, got %q", output)
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

func TestPrintf_ConsoleEnabled(t *testing.T) {
	resetDebugLogState(t)
	withFixedTime(t, time.Date(2026, time.June, 7, 14, 23, 11, 482000000, time.FixedZone("MSK", 3*60*60)))
	resolver.Options["Debug"] = strconv.FormatBool(true)
	resolver.Options["DebugConsole"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")
	defer delete(resolver.Options, "DebugConsole")

	log := New("console")
	output := captureStderr(t, func() {
		log.Printf("visible")
	})

	expected := "[2026-06-07T14:23:11.482+03:00] [console-debug] visible\n"
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

func TestPrintf_Format(t *testing.T) {
	resetDebugLogState(t)
	withFixedTime(t, time.Date(2026, time.June, 7, 14, 23, 11, 482000000, time.FixedZone("MSK", 3*60*60)))
	resolver.Options["Debug"] = strconv.FormatBool(true)
	resolver.Options["DebugConsole"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")
	defer delete(resolver.Options, "DebugConsole")

	log := New("dns")
	output := captureStderr(t, func() {
		log.Printf("target=%q qtype=%d", "example.com", 257)
	})

	if !strings.HasPrefix(output, "[2026-06-07T14:23:11.482+03:00] [dns-debug] ") {
		t.Errorf("expected timestamped prefix, got %q", output)
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
	withFixedTime(t, time.Date(2026, time.June, 7, 14, 23, 11, 482000000, time.FixedZone("MSK", 3*60*60)))
	resolver.Options["Debug"] = strconv.FormatBool(true)
	defer delete(resolver.Options, "Debug")
	delete(resolver.Options, "DebugConsole")

	if err := os.WriteFile(testDebugLogFile, []byte("old data\n"), 0o600); err != nil {
		t.Fatalf("failed to seed debug log file: %v", err)
	}

	log := New("fresh")
	output := captureStderr(t, func() {
		log.Printf("new data")
	})
	if output != "" {
		t.Errorf("expected no console output when DebugConsole is unset, got %q", output)
	}

	fileOutput, err := os.ReadFile(testDebugLogFile)
	if err != nil {
		t.Fatalf("failed to read debug log file: %v", err)
	}
	if string(fileOutput) != "[2026-06-07T14:23:11.482+03:00] [fresh-debug] new data\n" {
		t.Errorf("expected file output %q, got %q", "[2026-06-07T14:23:11.482+03:00] [fresh-debug] new data\n", string(fileOutput))
	}
}

func TestGetDebugLogFile_OpenError(t *testing.T) {
	resetDebugLogState(t)
	debugLogPath = "."

	if file := getDebugLogFile(); file != nil {
		t.Fatalf("expected nil file for invalid debug log path, got %v", file)
	}
	if file := getDebugLogFile(); file != nil {
		t.Fatalf("expected nil file for cached open error, got %v", file)
	}
	if errDebugLog == nil {
		t.Fatal("expected cached open error")
	}
}

func TestWriteString_IgnoresWriterError(_ *testing.T) {
	writeString(failingWriter{}, "hello")
}

func TestIsConsoleEnabled(t *testing.T) {
	oldDebug, hadDebug := resolver.Options["Debug"]
	oldDebugConsole, hadDebugConsole := resolver.Options["DebugConsole"]
	defer func() {
		if hadDebug {
			resolver.Options["Debug"] = oldDebug
		} else {
			delete(resolver.Options, "Debug")
		}
		if hadDebugConsole {
			resolver.Options["DebugConsole"] = oldDebugConsole
		} else {
			delete(resolver.Options, "DebugConsole")
		}
	}()

	tests := []struct {
		name         string
		debug        string
		debugConsole string
		want         bool
	}{
		{name: "debug disabled", debug: strconv.FormatBool(false), debugConsole: strconv.FormatBool(true), want: false},
		{name: "console disabled", debug: strconv.FormatBool(true), debugConsole: strconv.FormatBool(false), want: false},
		{name: "console enabled", debug: strconv.FormatBool(true), debugConsole: strconv.FormatBool(true), want: true},
		{name: "console unset", debug: strconv.FormatBool(true), debugConsole: "", want: false},
	}

	for _, tt := range tests {
		resolver.Options["Debug"] = tt.debug
		if tt.debugConsole == "" {
			delete(resolver.Options, "DebugConsole")
		} else {
			resolver.Options["DebugConsole"] = tt.debugConsole
		}

		if got := isConsoleEnabled(); got != tt.want {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.want, got)
		}
	}
}
