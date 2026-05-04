// Package modutil provides helper functions for initializing and
// populating schema.ModuleExecution, eliminating the repetitive
// boilerplate found in every DNS handler and other modules.
package modutil

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/schema"
)

// NewExecution creates a ModuleExecution with the given function name
// and a pre-allocated empty Results slice (never nil).
func NewExecution(functionName string) schema.ModuleExecution {
	return schema.ModuleExecution{
		Function: functionName,
		Results:  []schema.ModuleResult{},
	}
}

// SetError assigns a formatted error message to the execution.
// The format string should contain a single %v verb for the error.
func SetError(exec *schema.ModuleExecution, format string, err error) {
	msg := fmt.Sprintf(format, err)
	exec.Error = &msg
}

// SetRawFromBytes sets RawData from a byte slice if non-empty.
// It is a no-op when raw is nil or zero-length.
func SetRawFromBytes(exec *schema.ModuleExecution, raw []byte) {
	if len(raw) > 0 {
		exec.RawData = string(raw)
	}
}

// SetRawFallback sets RawData from raw bytes when available, otherwise
// falls back to joining the records slice with the given separator.
// It is a no-op when both sources are empty.
func SetRawFallback(exec *schema.ModuleExecution, raw []byte, records []string, sep string) {
	if len(raw) > 0 {
		exec.RawData = string(raw)
		return
	}
	if len(records) > 0 {
		exec.RawData = strings.Join(records, sep)
	}
}
