// Package dnsutils provides DNS-specific utility functions shared
// across DNS module handlers.
package dnsutils

import (
	"encoding/hex"
	"strings"
)

// DecodeWireFormat decodes an RFC 3597 generic record representation
// of the form "\# <length> <hex_data>" into raw bytes.
//
// The minDataLen parameter specifies the minimum number of decoded
// bytes required for the record to be considered valid (e.g. 3 for
// SSHFP which needs algorithm + fp type + at least one fp byte).
//
// Returns the decoded bytes and true on success, or nil and false if
// the input is not in RFC 3597 format, contains invalid hex, or the
// decoded data is shorter than minDataLen.
func DecodeWireFormat(raw string, minDataLen int) ([]byte, bool) {
	if !strings.HasPrefix(raw, "\\# ") {
		return nil, false
	}

	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return nil, false
	}

	hexStr := strings.ReplaceAll(fields[2], " ", "")
	if hexStr == "" {
		return nil, false
	}

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, false
	}

	if len(data) < minDataLen {
		return nil, false
	}

	return data, true
}
