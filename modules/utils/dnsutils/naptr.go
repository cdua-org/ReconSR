package dnsutils

import (
	"strings"
	"unicode"
)

// NAPTRRecord represents a parsed NAPTR DNS record.
type NAPTRRecord struct {
	Service      string
	Regexp       string
	RegexpTarget string
	Replacement  string
	Formatted    string
}

// ParseNAPTR parses a raw NAPTR record string.
func ParseNAPTR(raw string) *NAPTRRecord {
	if strings.HasPrefix(raw, "\\# ") {
		return nil
	}

	parts := splitNAPTRParts(raw)
	if len(parts) < 5 {
		return nil
	}

	service := strings.Trim(parts[3], "\"")
	regexpField, replacement := extractNAPTRFields(parts)
	regexpTarget := extractNAPTRRegexpTarget(regexpField)

	if replacement == service || replacement == "." {
		replacement = ""
	}

	return &NAPTRRecord{
		Service:      service,
		Regexp:       regexpField,
		RegexpTarget: regexpTarget,
		Replacement:  replacement,
		Formatted:    raw,
	}
}

func splitNAPTRParts(raw string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, r := range raw {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case unicode.IsSpace(r) && !inQuotes:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func extractNAPTRFields(parts []string) (regexpField, replacement string) {
	if len(parts) >= 6 {
		return strings.Trim(parts[4], "\""), parts[len(parts)-1]
	}
	if strings.HasPrefix(parts[4], "\"") {
		return strings.Trim(parts[4], "\""), ""
	}
	return "", parts[4]
}

func extractNAPTRRegexpTarget(regexpField string) string {
	if regexpField != "" && len(regexpField) > 3 {
		delim := string(regexpField[0])
		pieces := strings.Split(regexpField, delim)
		if len(pieces) >= 4 {
			return pieces[2]
		}
	}
	return ""
}

// CleanSRVTarget strips leading SRV-style service and protocol prefixes (e.g., _sip._tcp.) from a target domain.
func CleanSRVTarget(target string) string {
	target = strings.TrimSpace(strings.TrimSuffix(target, "."))
	labels := strings.Split(target, ".")
	if len(labels) >= 4 && strings.HasPrefix(labels[0], "_") && strings.HasPrefix(labels[1], "_") {
		return strings.Join(labels[2:], ".")
	}
	return target
}
