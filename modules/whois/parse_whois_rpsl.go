package whois

import "strings"

func processHandles(parts []string, handleRoles map[string]string, currentRole *string, registryType string) bool {
	k := strings.TrimSpace(parts[0])
	v := strings.TrimSpace(parts[1])
	switch k {
	case "registrant":
		if registryType == "cz" || registryType == "ar" {
			handleRoles[v] = whoisRoleRegistrant
			return true
		}
	case "admin-c":
		handleRoles[v] = whoisRoleAdministrative
		return registryType == "cz" || registryType == "br"
	case "tech-c":
		handleRoles[v] = whoisRoleTechnical
		return registryType == "cz" || registryType == "br"
	case "owner-c":
		handleRoles[v] = whoisRoleAdministrative
		return registryType == "br"
	case "nic-hdl-br", "nic-hdl", "contact":
		if r, ok := handleRoles[v]; ok {
			*currentRole = r
			return true
		}
	case "nsset":
		*currentRole = whoisRoleNameServers
		return true
	}
	return false
}

func contactByRole(m *Metadata, role string) *Contact {
	switch role {
	case whoisRoleRegistrar:
		return &m.Registrar
	case whoisRoleRegistrant:
		return &m.Registrant
	case whoisRoleAdministrative:
		return &m.Admin
	case whoisRoleTechnical:
		return &m.Tech
	case whoisRoleBilling:
		return &m.Billing
	case whoisRoleAbuse:
		return &m.Abuse
	}
	return nil
}

func applyRPSLMatch(m *Metadata, currentRole, lineLower, field, val, registryType string) {
	if strings.HasPrefix(lineLower, "abuse-") {
		applyContactMatch(&m.Abuse, "abuse_"+field, "abuse_", val)
		return
	}

	var target *Contact
	switch currentRole {
	case whoisRoleRegistrar:
		target = &m.Registrar
	case whoisRoleAdministrative:
		target = &m.Admin
	case whoisRoleTechnical:
		target = &m.Tech
	case whoisRoleBilling:
		target = &m.Billing
	case whoisRoleAbuse:
		target = &m.Abuse
	default:
		target = &m.Registrant
	}

	if target != nil {
		switch field {
		case "name":
			if registryType == "ar" {
				target.Organization = appendUnique(target.Organization, val)
			} else {
				target.Name = appendUnique(target.Name, val)
			}
		case whoisFieldOrg:
			target.Organization = appendUnique(target.Organization, val)
		case whoisFieldEmail:
			target.Email = appendUnique(target.Email, val)
		case "addr":
			target.Address = appendUnique(target.Address, val)
		case "phone":
			target.Phone = appendUnique(target.Phone, val)
		case "fax":
			target.Fax = appendUnique(target.Fax, val)
		}
	}
}
