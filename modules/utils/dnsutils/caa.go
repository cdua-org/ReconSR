package dnsutils

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var caaRegex = regexp.MustCompile(`(?i)^\d+\s+(issue|issuewild|iodef|issuemail)\s+"(.*)"$`)

// DecodeHexCAA attempts to decode a hex-encoded CAA record into presentation format.
func DecodeHexCAA(raw string) (string, error) {
	data, ok := DecodeWireFormat(raw, 2)
	if !ok {
		return "", errors.New("invalid or too short CAA wire format")
	}

	flags := data[0]
	tagLen := int(data[1])
	if len(data) < 2+tagLen {
		return "", errors.New("tag length mismatch")
	}

	tag := string(data[2 : 2+tagLen])
	value := string(data[2+tagLen:])

	return strconv.Itoa(int(flags)) + " " + tag + " \"" + value + "\"", nil
}

// ParseCAA parses a raw CAA record string and returns the normalized representation, tag, value, and whether it matched.
func ParseCAA(data string) (normalized, tag, val string, matched bool) {
	normalized = data
	if strings.HasPrefix(normalized, "\\#") {
		if decoded, err := DecodeHexCAA(normalized); err == nil {
			normalized = decoded
		}
	}

	matches := caaRegex.FindStringSubmatch(normalized)
	if len(matches) < 3 {
		return normalized, "", "", false
	}

	tag = strings.ToLower(strings.TrimSpace(matches[1]))
	val = strings.TrimSpace(matches[2])
	return normalized, tag, val, true
}

// ExtractCAAAuthority extracts the authority domain from a CAA issue/issuewild value.
func ExtractCAAAuthority(val string) string {
	parts := strings.SplitN(val, ";", 2)
	return strings.TrimSpace(parts[0])
}

// ExtractCAAIodefEmail extracts the email address from a CAA iodef mailto value.
func ExtractCAAIodefEmail(val string) string {
	if len(val) < len("mailto:") || !strings.EqualFold(val[:len("mailto:")], "mailto:") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(val[len("mailto:"):], "//"))
}
