package whois

// applyAustrianMatch routes Austrian (.at) WHOIS-specific regex matches
// to metadata fields. Address fields (city, country, street address,
// postal code) are handled by rpsl_addr with context-aware routing.
func applyAustrianMatch(m *Metadata, key, val string) {
	switch key {
	case "at_changed":
		if m.UpdatedDate == "" {
			m.UpdatedDate = val
		}
	case "at_nserver":
		addNameServer(m, val)
	case "at_registrar":
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
	case "at_registrant":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case "at_tech_c":
		m.Tech.Name = appendUnique(m.Tech.Name, val)
	case "at_admin_c":
		m.Admin.Name = appendUnique(m.Admin.Name, val)
	case "at_personname":
		m.Registrant.Name = appendUnique(m.Registrant.Name, val)
	case "at_organization":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	}
}
