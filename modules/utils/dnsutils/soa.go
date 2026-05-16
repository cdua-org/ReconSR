package dnsutils

import (
	"strconv"
	"strings"
)

// SOA represents the parsed SOA record data.
type SOA struct {
	NS      string
	Mbox    string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	MinTTL  uint32
}

// ParseSOA parses a raw SOA record string into an SOA struct.
func ParseSOA(data string) *SOA {
	parts := strings.Fields(data)
	if len(parts) < 7 {
		return nil
	}

	return &SOA{
		NS:      parts[0],
		Mbox:    parts[1],
		Serial:  parseUint(parts[2]),
		Refresh: parseUint(parts[3]),
		Retry:   parseUint(parts[4]),
		Expire:  parseUint(parts[5]),
		MinTTL:  parseUint(parts[6]),
	}
}

func parseUint(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// FormatSOAMbox converts an SOA mailbox (rname) string into a standard email address format.
func FormatSOAMbox(mbox string) string {
	mbox = strings.TrimSuffix(mbox, ".")
	if before, _, found := strings.Cut(mbox, "."); found {
		return before + "@" + mbox[len(before)+1:]
	}
	return mbox
}
