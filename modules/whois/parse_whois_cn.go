package whois

func applyCNMatch(m *Metadata, key, val string) {
	switch key {
	case whoisFieldCNRegistrant:
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case whoisFieldCNRegistrantEmail:
		m.Registrant.Email = appendUnique(m.Registrant.Email, val)
	}
}
