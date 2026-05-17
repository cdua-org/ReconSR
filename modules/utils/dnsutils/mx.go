package dnsutils

import (
	"errors"
	"strings"
)

// ParseMXHost extracts the mail exchange host from an MX record data string.
// The input format is "priority host" (e.g., "10 mail.example.com.").
// Returns the host with any trailing dot stripped.
func ParseMXHost(data string) (string, error) {
	parts := strings.Fields(data)
	if len(parts) < 2 {
		return "", errors.New("invalid MX record format")
	}

	host := strings.TrimSuffix(parts[1], ".")
	if host == "" {
		return "", errors.New("empty MX host")
	}

	return host, nil
}
