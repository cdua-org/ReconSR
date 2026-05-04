package whois

import "slices"

func applyJPMatch(m *Metadata, key, val string) {
	if applyJPDomainMatch(m, key, val) {
		return
	}
	applyJPContactMatch(m, key, val)
}

func applyJPDomainMatch(m *Metadata, key, val string) bool {
	switch key {
	case "jp_registered", "jp_connected", "jp2_created":
		if m.CreationDate == "" {
			m.CreationDate = val
		}
		return true
	case "jp_last_update", "jp2_updated":
		if m.UpdatedDate == "" {
			m.UpdatedDate = val
		}
		return true
	case "jp2_expires":
		if m.ExpirationDate == "" {
			m.ExpirationDate = val
		}
		return true
	case "ns_jp", "jp2_ns":
		addNameServer(m, val)
		return true
	case "jp_state", "jp_lock", "jp2_status", "jp2_lock":
		if !slices.Contains(m.DomainStatus, val) {
			m.DomainStatus = append(m.DomainStatus, val)
		}
		return true
	case "jp_domain", "jp_org_type":
		// Informational only, no metadata mapping required.
		return true
	}
	return false
}

func applyJPContactMatch(m *Metadata, key, val string) {
	switch key {
	case "jp_org", "jp2_registrant":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case "jp2_contact_name":
		m.Registrant.Name = appendUnique(m.Registrant.Name, val)
	case "jp2_contact_email":
		m.Registrant.Email = appendUnique(m.Registrant.Email, val)
	case "jp2_postal_code", "jp2_address":
		m.Registrant.Address = appendUnique(m.Registrant.Address, val)
	case "jp2_phone":
		m.Registrant.Phone = appendUnique(m.Registrant.Phone, val)
	case "jp2_fax":
		m.Registrant.Phone = appendUnique(m.Registrant.Phone, val)
	case "jp_admin":
		m.Admin.Name = appendUnique(m.Admin.Name, val)
	case "jp_tech":
		m.Tech.Name = appendUnique(m.Tech.Name, val)
	}
}
