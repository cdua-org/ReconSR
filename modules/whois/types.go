package whois

import (
	"slices"
	"strings"
)

const (
	roleRegistrar      = "registrar"
	roleRegistrant     = "registrant"
	roleAdministrative = "administrative"
	roleTechnical      = "technical"
	roleBilling        = "billing"
	roleAbuse          = "abuse"
	roleNameServers    = "nameservers"

	fieldOrg        = "org"
	fieldEmail      = "email"
	fieldExpiration = "expiration"
	fieldURL        = "url"
	fieldStatus     = "status"
)

// Contact represents parsed contact information from WHOIS/RDAP data.
type Contact struct {
	Name         []string
	Organization []string
	Email        []string
	Address      []string
	Phone        []string
	Fax          []string
}

// Metadata represents parsed domain registration metadata.
type Metadata struct {
	NameServers    []string
	DomainStatus   []string
	CreationDate   string
	ExpirationDate string
	UpdatedDate    string
	RegistrarURL   string
	WhoisServer    string
	DNSSEC         string
	IANAID         string
	Registrar      Contact
	Registrant     Contact
	Admin          Contact
	Tech           Contact
	Billing        Contact
	Abuse          Contact
}

func safeString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if list, ok := v.([]any); ok {
		var parts []string
		for _, item := range list {
			if s, ok := item.(string); ok {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		var nonEmpty []string
		for _, p := range parts {
			if p != "" {
				nonEmpty = append(nonEmpty, p)
			}
		}
		return strings.Join(nonEmpty, ", ")
	}
	return ""
}

func isRedacted(val string) bool {
	lower := strings.ToLower(val)
	markers := []string{
		"redacted",
		"not disclosed",
		"please query",
		"data protected",
		"registration private",
		"contact privacy",
		"withheld for privacy",
		"select request email form",
		"visit www.icann.org",
		"not applicable",
		"gdpr masked",
		"statutory masking",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func appendUnique(slice []string, val string) []string {
	val = strings.TrimSpace(val)
	if val == "" || isRedacted(val) {
		return slice
	}
	if slices.Contains(slice, val) {
		return slice
	}
	return append(slice, val)
}

func normalizePhone(phone string) string {
	phone = strings.ToLower(strings.TrimSpace(phone))
	phone = strings.TrimPrefix(phone, "tel:")
	phone = strings.TrimPrefix(phone, "phone:")

	hasPlus := strings.HasPrefix(phone, "+")

	var digits []rune
	for _, r := range phone {
		if (r >= '0' && r <= '9') || r == '+' {
			digits = append(digits, r)
		}
	}

	result := strings.TrimSpace(string(digits))
	if hasPlus && !strings.HasPrefix(result, "+") {
		result = "+" + result
	}

	result = strings.ReplaceAll(result, "+", "")

	var cleaned []rune
	for _, r := range result {
		if r >= '0' && r <= '9' {
			cleaned = append(cleaned, r)
		}
	}

	if len(cleaned) >= 10 {
		return "+" + string(cleaned)
	}
	return ""
}

func isPrivacyService(org string) bool {
	low := strings.ToLower(org)
	keywords := []string{
		"privacy", "redacted", "proxy", "whoisguard", "whoisprivacy",
		"protection", "masked", "not disclosed", "customer care",
	}
	for _, kw := range keywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}
