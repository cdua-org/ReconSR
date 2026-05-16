package dnsutils

import "strings"

// ParseDMARC parses a DMARC record into a key-value map.
func ParseDMARC(record string) map[string]string {
	result := make(map[string]string)

	record = strings.TrimSpace(record)
	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			result[key] = value
		}
	}

	return result
}

// ExtractDMARCEmails extracts email addresses from a DMARC URI list (e.g. from rua/ruf).
func ExtractDMARCEmails(val string) []string {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "mailto:")

	var emails []string
	for part := range strings.SplitSeq(val, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "mailto:")
		if part != "" && strings.Contains(part, "@") {
			emails = append(emails, part)
		}
	}
	return emails
}
