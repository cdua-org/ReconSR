// Package debuglog provides a lightweight, module-scoped debug logger
// controlled by the global Debug resolver option. It replaces scattered
// isDebug() copies and ad-hoc fmt.Fprintf(os.Stderr, ...) calls with a
// single, consistent API that produces zero allocations when disabled.
package debuglog

import (
	"fmt"
	"io"
	"os"
	"sync"

	"cdua-org/ReconSR/modules/utils/resolver"
)

// Logger emits prefixed debug messages to stderr and lazily mirrors them
// into a debug.log file in the current working directory when the global
// Debug option is enabled. It is a value type — safe to store as a
// package-level variable without heap allocation.
type Logger struct {
	prefix string
}

var (
	debugLogPath = "debug.log"
	debugLogFile *os.File
	errDebugLog  error
	debugLogOnce sync.Once
	writeMu      sync.Mutex
)

// New creates a Logger that tags every message with "[tag-debug] ".
func New(tag string) Logger {
	return Logger{prefix: "[" + tag + "-debug] "}
}

// Printf writes a formatted debug message to stderr when Debug=true.
// It lazily mirrors the same output into debug.log and remains a complete
// no-op when debug is disabled.
func (l Logger) Printf(format string, args ...any) {
	if !isEnabled() {
		return
	}

	line := fmt.Sprintf(l.prefix+format+"\n", args...)

	writeMu.Lock()
	defer writeMu.Unlock()

	writeString(os.Stderr, line)
	if file := getDebugLogFile(); file != nil {
		writeString(file, line)
	}
}

func getDebugLogFile() *os.File {
	debugLogOnce.Do(func() {
		debugLogFile, errDebugLog = os.OpenFile(debugLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	})
	if errDebugLog != nil {
		return nil
	}
	return debugLogFile
}

func writeString(w io.Writer, line string) {
	if _, err := io.WriteString(w, line); err != nil {
		return
	}
}

func isEnabled() bool {
	val, ok := resolver.GetOption("Debug")
	return ok && val == "true"
}
