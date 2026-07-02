package whois

import (
	"regexp"
	"slices"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
)

var postalCodeRe = regexp.MustCompile(`^\d{4,6}$`)

var addressTokens = []string{
	"IT", "US", "UK", "DE", "FR", "ES", "AT", "CH", "NL", "BE",
	"MI", "RM", "TO", "NA", "BA", "PA", "VE", "FI", "BO", "MO",
	"CT", "TA", "VA", "BS", "PD", "VR", "GE", "FC", "PI",
	"MILANO", "ROMA", "NAPOLI", "TORINO", "PALERMO", "GENOVA",
	"BOLOGNA", "FIRENZE", "BARI", "CATANIA", "VERONA", "PADOVA",
	"VENEZIA", "TRIESTE", "BRESCIA", "CAGLIARI", "MESSINA",
	"TARANTO", "ROMAGNA",
}

func detectRegistry(rawLower string) string {
	if strings.Contains(rawLower, "\nnic-hdl-br:") || strings.Contains(rawLower, "\nownerid:") {
		return "br"
	}
	if strings.Contains(rawLower, "\nnsset:") {
		return "cz"
	}
	if strings.Contains(rawLower, "\nregistrar:   nicar") || strings.Contains(rawLower, ".com.ar\n") {
		return "ar"
	}
	return ""
}

func isContinuation(rawLine, line, lastKey string) bool {
	return lastKey != "" && leadingSpaces(rawLine) >= 16 && !strings.HasPrefix(line, "[")
}

func isPlaceholder(val string) bool {
	v := strings.ToLower(val)
	return v == "n/a" || v == "none" || v == "null" || v == "-" || v == "." || v == "not applicable"
}

func skipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//")
}

func isFooterMarker(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(line, ">>>") ||
		strings.HasPrefix(lower, "notice:") ||
		strings.HasPrefix(lower, "terms of use:") ||
		strings.HasPrefix(lower, "the registry database contains")
}

func isDomainLevelKey(key string) bool {
	switch key {
	case constants.TypeDomain, whoisFieldStatus, whoisFieldNameServer, whoisFieldDNSSEC, whoisFieldCreation, whoisFieldUpdated, whoisFieldExpiration,
		whoisFieldWhoisServer, whoisFieldIANAID, whoisFieldURL:
		return true
	}
	return false
}

func isFreeformLine(rawLine, line, currentRole string) bool {
	return currentRole != "" && (isIndented(rawLine) || !strings.Contains(line, ":"))
}

func addNameServer(m *Metadata, val string) {
	hostname := strings.TrimSuffix(strings.TrimSpace(val), ".")
	if hostname == "" || !strings.Contains(hostname, ".") {
		return
	}
	hostname = strings.ToLower(hostname)
	if !slices.Contains(m.NameServers, hostname) {
		m.NameServers = append(m.NameServers, hostname)
	}
}

func leadingSpaces(rawLine string) int {
	return len(rawLine) - len(strings.TrimLeft(rawLine, " "))
}

func applyContinuation(m *Metadata, lastKey, currentRole, val string) {
	switch lastKey {
	case whoisFieldRPSLAddr:
		if target := contactByRole(m, currentRole); target != nil {
			target.Address = appendUnique(target.Address, val)
		}
	case "reg_addr":
		m.Registrant.Address = appendUnique(m.Registrant.Address, val)
	case "admin_addr":
		m.Admin.Address = appendUnique(m.Admin.Address, val)
	case "tech_addr":
		m.Tech.Address = appendUnique(m.Tech.Address, val)
	case "billing_addr":
		m.Billing.Address = appendUnique(m.Billing.Address, val)
	case whoisFieldJP2Address, whoisFieldJP2PostalCode, whoisFieldKRRegZip:
		m.Registrant.Address = appendUnique(m.Registrant.Address, val)
	case whoisFieldNameServer:
		addNameServer(m, strings.Fields(val)[0])
	}
}

func classifyIndentedLine(m *Metadata, role, line string, lineIndex int) {
	if role == whoisRoleNameServers {
		addNameServer(m, strings.Fields(line)[0])
		return
	}

	var target *Contact
	switch role {
	case whoisRoleRegistrar:
		target = &m.Registrar
	case whoisRoleRegistrant:
		target = &m.Registrant
	case whoisRoleAdministrative:
		target = &m.Admin
	case whoisRoleTechnical:
		target = &m.Tech
	case whoisRoleAbuse:
		target = &m.Abuse
	case whoisRoleBilling:
		target = &m.Billing
	default:
		return
	}

	switch {
	case strings.Contains(line, "@"):
		target.Email = appendUnique(target.Email, line)
	case strings.HasPrefix(line, "+"):
		target.Phone = appendUnique(target.Phone, line)
	case lineIndex == 0 && !isLikelyAddress(line):
		target.Name = appendUnique(target.Name, line)
	case lineIndex == 1 && !strings.ContainsAny(line, "0123456789"):
		target.Organization = appendUnique(target.Organization, line)
	default:
		target.Address = appendUnique(target.Address, line)
	}
}

func isIndented(rawLine string) bool {
	return strings.HasPrefix(rawLine, "\t") || strings.HasPrefix(rawLine, "  ")
}

func isLikelyAddress(line string) bool {
	upper := strings.ToUpper(line)
	if slices.Contains(addressTokens, upper) {
		return true
	}
	return postalCodeRe.MatchString(line)
}

func cleanWhoisServer(val string) string {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "http://")
	val = strings.TrimPrefix(val, "https://")
	return strings.TrimSuffix(val, "/")
}

func applyRegistrarMatch(m *Metadata, key, val string) bool {
	switch key {
	case whoisRoleRegistrar:
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
		return true
	case constants.TypeURL, "url_bare":
		if m.RegistrarURL == "" {
			m.RegistrarURL = val
		}
		return true
	case whoisFieldWhoisServer:
		if m.WhoisServer == "" {
			m.WhoisServer = cleanWhoisServer(val)
		}
		return true
	case whoisFieldIANAID:
		if m.IANAID == "" {
			m.IANAID = val
		}
		return true
	case whoisFieldDNSSEC:
		m.DNSSEC = val
		return true
	}
	return false
}

func applyContactMatch(c *Contact, key, prefix, val string) bool {
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	field := strings.TrimPrefix(key, prefix)
	switch field {
	case whoisFieldOrg:
		c.Organization = appendUnique(c.Organization, val)
		return true
	case "name":
		c.Name = appendUnique(c.Name, val)
		return true
	case whoisFieldEmail:
		c.Email = appendUnique(c.Email, val)
		return true
	case "addr":
		c.Address = appendUnique(c.Address, val)
		return true
	case "phone":
		c.Phone = appendUnique(c.Phone, val)
		return true
	case "fax":
		c.Fax = appendUnique(c.Fax, val)
		return true
	}
	return false
}

func applyDomainMatch(m *Metadata, key, val string) {
	switch key {
	case whoisFieldCreation:
		if m.CreationDate == "" {
			m.CreationDate = val
		}
	case whoisFieldUpdated:
		if m.UpdatedDate == "" {
			m.UpdatedDate = val
		}
	case whoisFieldExpiration:
		if m.ExpirationDate == "" {
			m.ExpirationDate = val
		}
	case whoisFieldNameServer:
		addNameServer(m, val)
	case whoisFieldStatus:
		if !slices.Contains(m.DomainStatus, val) {
			m.DomainStatus = append(m.DomainStatus, val)
		}
	case whoisFieldCNRegistrant:
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case whoisFieldCNRegistrantEmail:
		m.Registrant.Email = appendUnique(m.Registrant.Email, val)
	}
}
