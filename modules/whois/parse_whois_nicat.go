package whois

func applyAustrianMatch(m *Metadata, key, val string) {
	switch key {
	case "at_changed":
		if m.UpdatedDate == "" {
			m.UpdatedDate = val
		}
	case "at_nserver":
		addNameServer(m, val)
	case "at_tech_c":
		m.Tech.Name = appendUnique(m.Tech.Name, val)
	case "at_admin_c":
		m.Admin.Name = appendUnique(m.Admin.Name, val)
	}
}
