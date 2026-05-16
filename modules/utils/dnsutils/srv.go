package dnsutils

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParseSRVHost parses an SRV record data string and extracts the target host.
func ParseSRVHost(data string) (string, error) {
	parts := strings.Fields(data)
	if len(parts) < 4 {
		return "", errors.New("invalid SRV record format")
	}

	host := strings.TrimSuffix(parts[3], ".")
	if host == "" {
		return "", errors.New("invalid SRV host")
	}

	for i := range 3 {
		if _, err := strconv.ParseUint(parts[i], 10, 16); err != nil {
			return "", fmt.Errorf("invalid numeric field %d: %w", i, err)
		}
	}

	return host, nil
}
