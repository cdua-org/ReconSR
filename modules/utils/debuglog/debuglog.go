// Package debuglog provides a lightweight, module-scoped debug logger
// controlled by the global Debug resolver option. It replaces scattered
// isDebug() copies and ad-hoc fmt.Fprintf(os.Stderr, ...) calls with a
// single, consistent API that produces zero allocations when disabled.
package debuglog

import (
	"fmt"
	"os"

	"cdua-org/ReconSR/modules/utils/resolver"
)

// Logger emits prefixed debug messages to stderr when the global
// Debug option is enabled. It is a value type — safe to store as
// a package-level variable without heap allocation.
type Logger struct {
	prefix string
}

// New creates a Logger that tags every message with "[tag-debug] ".
func New(tag string) Logger {
	return Logger{prefix: "[" + tag + "-debug] "}
}

// Printf writes a formatted debug message to stderr when Debug=true.
// It is a complete no-op (zero allocations) when debug is disabled.
func (l Logger) Printf(format string, args ...any) {
	if !isEnabled() {
		return
	}
	fmt.Fprintf(os.Stderr, l.prefix+format+"\n", args...)
}

func isEnabled() bool {
	val, ok := resolver.GetOption("Debug")
	return ok && val == "true"
}
