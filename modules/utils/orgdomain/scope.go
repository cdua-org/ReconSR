package orgdomain

import "strings"

// IsOutOfScope reports whether entity belongs to a different organization
// than target based on their organizational domains (eTLD+1).
//
// When GetOrganizationalDomain returns "" for either argument (e.g. bare
// TLDs or invalid input), it falls back to a direct domain/suffix
// comparison — replicating the guard logic from the dmarc handler.
func IsOutOfScope(entity, target string) bool {
	entity = strings.TrimSuffix(strings.ToLower(entity), ".")
	target = strings.TrimSuffix(strings.ToLower(target), ".")

	if entity == "" || target == "" {
		return false
	}

	entityOrg := GetOrganizationalDomain(entity)
	targetOrg := GetOrganizationalDomain(target)

	if entityOrg != "" && targetOrg != "" {
		return entityOrg != targetOrg
	}

	// Fallback: direct domain or suffix comparison when eTLD+1 is unavailable.
	return entity != target && !strings.HasSuffix(entity, "."+target)
}

// IsEmailOutOfScope extracts the domain part from an email address and
// delegates to IsOutOfScope. It returns false for malformed addresses
// (no '@' or empty domain) to avoid false-positive scope filtering.
func IsEmailOutOfScope(email, target string) bool {
	_, domain, ok := strings.Cut(email, "@")
	if !ok || domain == "" {
		return false
	}
	return IsOutOfScope(domain, target)
}
