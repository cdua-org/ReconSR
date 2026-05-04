// Package orgdomain provides utility functions for ReconSR modules.
package orgdomain

import (
	"golang.org/x/net/publicsuffix"
)

// GetOrganizationalDomain returns the eTLD+1 (organizational domain) for a given domain.
func GetOrganizationalDomain(domain string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return ""
	}
	return org
}
