package whois

func applyKRMatch(m *Metadata, key, val string) {
	switch key {
	case "kr_hostname":
		addNameServer(m, val)
	case "kr_agency":
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
	case "kr_ac_name":
		m.Admin.Name = appendUnique(m.Admin.Name, val)
	case "kr_ac_email":
		m.Admin.Email = appendUnique(m.Admin.Email, val)
	case "kr_ac_phone":
		m.Admin.Phone = appendUnique(m.Admin.Phone, val)
	case whoisFieldKRRegZip:
		m.Registrant.Address = appendUnique(m.Registrant.Address, val)
	}
}
