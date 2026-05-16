package dnsutils

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// URIRecord represents a parsed URI DNS record.
type URIRecord struct {
	Priority  string
	Weight    string
	Target    string
	Formatted string
}

// ParseURI parses a raw URI record string, handling both RFC3597 wire format and plain text.
func ParseURI(raw string) *URIRecord {
	data, ok := DecodeWireFormat(raw, 4)
	if ok {
		priority := binary.BigEndian.Uint16(data[0:2])
		weight := binary.BigEndian.Uint16(data[2:4])
		target := string(data[4:])

		return &URIRecord{
			Priority:  strconv.FormatUint(uint64(priority), 10),
			Weight:    strconv.FormatUint(uint64(weight), 10),
			Target:    target,
			Formatted: fmt.Sprintf("%d %d %q", priority, weight, target),
		}
	}

	parts := strings.Fields(raw)
	if len(parts) >= 3 {
		priority := parts[0]
		weight := parts[1]
		target := strings.Trim(strings.Join(parts[2:], " "), "\"")
		return &URIRecord{
			Priority:  priority,
			Weight:    weight,
			Target:    target,
			Formatted: fmt.Sprintf("%s %s %q", priority, weight, target),
		}
	}

	return nil
}
