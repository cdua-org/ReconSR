package whois

import "strings"

func extractTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return domain
}

func buildRDAPURL(domain string) string {
	tld := extractTLD(domain)
	if customServer := getRDAPServer(tld); customServer != "" {
		return customServer + "domain/" + domain
	}
	return "https://rdap.org/domain/" + domain
}
