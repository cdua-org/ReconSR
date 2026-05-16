package dnsutils

import (
	"strings"
)

// HINFORecord represents a parsed HINFO DNS record.
type HINFORecord struct {
	CPU       string
	OS        string
	Formatted string
}

// ParseHINFO parses a raw HINFO record string into its CPU and OS components.
func ParseHINFO(raw string) *HINFORecord {
	parts := strings.Fields(raw)
	if len(parts) >= 2 {
		cpu := strings.Trim(parts[0], "\"")
		osStr := strings.Trim(strings.Join(parts[1:], " "), "\"")

		return &HINFORecord{
			CPU:       cpu,
			OS:        osStr,
			Formatted: raw,
		}
	}
	return nil
}
