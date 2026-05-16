package dnsutils

import "strings"

// ParseNSEC extracts the next domain name from an NSEC record data string.
func ParseNSEC(data string) string {
	parts := strings.Fields(data)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// ParseNSEC3 extracts the next hashed owner name from an NSEC3 record data string.
func ParseNSEC3(data string) string {
	parts := strings.Fields(data)
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// ExtractNSEC3Hash extracts the hash portion from an NSEC3 record name.
func ExtractNSEC3Hash(name string) string {
	hashPart, _, _ := strings.Cut(name, ".")
	return hashPart
}
