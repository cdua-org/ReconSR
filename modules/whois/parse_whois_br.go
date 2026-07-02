package whois

func applyBRMatch(m *Metadata, key, val string) {
	switch key {
	case "br_owner":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case "br_ownerid":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	}
}
