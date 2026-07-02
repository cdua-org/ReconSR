package whois

func applyTWMatch(m *Metadata, key, val string) {
	switch key {
	case "tw_created":
		if m.CreationDate == "" {
			m.CreationDate = val
		}
	case "tw_expires":
		if m.ExpirationDate == "" {
			m.ExpirationDate = val
		}
	case "tw_registrar":
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
	case "tw_url":
		if m.RegistrarURL == "" {
			m.RegistrarURL = val
		}
	}
}
