package whois

import (
	"bufio"
	"regexp"
	"strings"
)

var whoisPatterns = map[string]*regexp.Regexp{
	"registrar":   regexp.MustCompile(`(?i)Registrar:\s+(.*)`),
	"url":         regexp.MustCompile(`(?i)(?:Registrar\s+)?URL:\s+(.*)`),
	"whoisserver": regexp.MustCompile(`(?i)Registrar\s+WHOIS\s+Server:\s+(.*)`),
	"ianaid":      regexp.MustCompile(`(?i)Registrar\s+IANA\s+ID:\s+(.*)`),
	"dnssec":      regexp.MustCompile(`(?i)DNSSEC:\s+(.*)`),

	"creation":   regexp.MustCompile(`(?i)(Creation|Created|Registered(?:\s+on)?|Activated)(?:\s+Date)?:\s+(.*)`),
	"updated":    regexp.MustCompile(`(?i)(Updated|Last\s+Updated|Modified)(?:\s+Date)?:\s+(.*)`),
	"expiration": regexp.MustCompile(`(?i)(Registry\s+Expiry|Expiration|Expiry|Expires)(?:\s+Date)?:\s+(.*)`),
	"ns":         regexp.MustCompile(`(?i)(Name\s+Server|nserver):\s+(.*)`),
	"status":     regexp.MustCompile(`(?i)(Domain\s+)?Status:\s+(.*)`),

	"reg_name":  regexp.MustCompile(`(?i)Registrant\s+Name:\s+(.*)`),
	"reg_org":   regexp.MustCompile(`(?i)Registrant\s+Organization:\s+(.*)`),
	"reg_email": regexp.MustCompile(`(?i)Registrant\s+Email:\s+(.*)`),
	"reg_addr":  regexp.MustCompile(`(?i)Registrant\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"reg_phone": regexp.MustCompile(`(?i)Registrant\s+Phone:\s+(.*)`),

	"admin_name":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Name:\s+(.*)`),
	"admin_org":   regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Organization:\s+(.*)`),
	"admin_email": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Email:\s+(.*)`),
	"admin_addr":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"admin_phone": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Phone:\s+(.*)`),

	"tech_name":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Name:\s+(.*)`),
	"tech_org":   regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Organization:\s+(.*)`),
	"tech_email": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Email:\s+(.*)`),
	"tech_addr":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"tech_phone": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Phone:\s+(.*)`),

	"billing_name":  regexp.MustCompile(`(?i)Billing\s+Name:\s+(.*)`),
	"billing_org":   regexp.MustCompile(`(?i)Billing\s+Organization:\s+(.*)`),
	"billing_email": regexp.MustCompile(`(?i)Billing\s+Email:\s+(.*)`),
	"billing_addr":  regexp.MustCompile(`(?i)Billing\s+(?:Street|Address|City|State/Province|Postal Code|Country):\s+(.*)`),
	"billing_phone": regexp.MustCompile(`(?i)Billing\s+Phone:\s+(.*)`),

	"abuse_email": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Email:\s+(.*)`),
	"abuse_phone": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Phone:\s+(.*)`),

	"rpsl_name":  regexp.MustCompile(`(?i)^\s*(?:person|name)(?:-loc)?:\s+(.*)`),
	"rpsl_org":   regexp.MustCompile(`(?i)^\s*(?:organization|org)(?:-loc)?:\s+(.*)`),
	"rpsl_email": regexp.MustCompile(`(?i)^\s*(?:e-mail|email|abuse-email):\s+(.*)`),
	"rpsl_addr":  regexp.MustCompile(`(?i)^\s*(?:address|street|city|state|postal-code|country|abuse-postal)(?:-loc)?:\s+(.*)`),
	"rpsl_phone": regexp.MustCompile(`(?i)^\s*(?:phone|tel|abuse-phone|fax)(?:-loc)?:\s+(.*)`),
}

func updateRoleContext(lineLower, currentRole string) string {
	switch {
	case strings.Contains(lineLower, "registrar:"):
		return roleRegistrar
	case strings.Contains(lineLower, "registrant:"):
		return roleRegistrant
	case strings.Contains(lineLower, "administrative contact:") ||
		strings.Contains(lineLower, "admin:") ||
		strings.Contains(lineLower, "administrative:"):
		return roleAdministrative
	case strings.Contains(lineLower, "technical contact:") ||
		strings.Contains(lineLower, "tech:") ||
		strings.Contains(lineLower, "technical:"):
		return roleTechnical
	case strings.Contains(lineLower, "abuse:"):
		return roleAbuse
	case strings.Contains(lineLower, "name servers:"):
		return roleNameServers
	}

	// Lines ending with ":" without a value indicate an unknown section
	// header (e.g., "Relevant dates:", "Registration status:"). Reset
	// role to prevent data leakage from prior sections.
	if strings.HasSuffix(lineLower, ":") {
		return ""
	}

	return currentRole
}

func applyRPSLMatch(m *Metadata, currentRole, lineLower, field, val string) {
	if strings.HasPrefix(lineLower, "abuse-") {
		applyContactMatch(&m.Abuse, "abuse_"+field, "abuse_", val)
		return
	}

	var target *Contact
	switch currentRole {
	case roleRegistrar:
		target = &m.Registrar
	case roleRegistrant:
		target = &m.Registrant
	case roleAdministrative:
		target = &m.Admin
	case roleTechnical:
		target = &m.Tech
	}

	if target != nil {
		switch field {
		case "name":
			target.Name = appendUnique(target.Name, val)
		case fieldOrg:
			target.Organization = appendUnique(target.Organization, val)
		case fieldEmail:
			target.Email = appendUnique(target.Email, val)
		case "addr":
			target.Address = appendUnique(target.Address, val)
		case "phone":
			target.Phone = appendUnique(target.Phone, val)
		}
	}
}

// classifyIndentedLine routes indented freeform lines (EDUCAUSE, .uk registry)
// to the appropriate contact field using content-based heuristics.
func classifyIndentedLine(m *Metadata, role, line string, lineIndex int) {
	if role == roleNameServers {
		host := strings.Fields(line)[0]
		if strings.Contains(host, ".") {
			m.NameServers = append(m.NameServers, strings.ToLower(host))
		}
		return
	}

	var target *Contact
	switch role {
	case roleRegistrar:
		target = &m.Registrar
	case roleRegistrant:
		target = &m.Registrant
	case roleAdministrative:
		target = &m.Admin
	case roleTechnical:
		target = &m.Tech
	case roleAbuse:
		target = &m.Abuse
	default:
		return
	}

	switch {
	case strings.Contains(line, "@"):
		target.Email = appendUnique(target.Email, line)
	case strings.HasPrefix(line, "+"):
		target.Phone = appendUnique(target.Phone, line)
	case lineIndex == 0:
		target.Name = appendUnique(target.Name, line)
	default:
		target.Address = appendUnique(target.Address, line)
	}
}

func isIndented(rawLine string) bool {
	return strings.HasPrefix(rawLine, "\t") || strings.HasPrefix(rawLine, "    ")
}

func parseWHOIS(raw string) Metadata {
	m := Metadata{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	currentRole := ""
	indentedIndex := 0

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		lineLower := strings.ToLower(line)

		newRole := updateRoleContext(lineLower, currentRole)
		roleChanged := newRole != currentRole
		if roleChanged {
			currentRole = newRole
			indentedIndex = 0
		}

		matched := false
		for key, re := range whoisPatterns {
			match := re.FindStringSubmatch(line)
			if len(match) <= 1 {
				continue
			}
			matched = true
			val := strings.TrimSpace(match[len(match)-1])

			if field, found := strings.CutPrefix(key, "rpsl_"); found {
				applyRPSLMatch(&m, currentRole, lineLower, field, val)
			} else {
				applyWHOISMatch(&m, key, val)
			}
		}

		// Fallback: indented freeform lines (EDUCAUSE tabs, .uk spaces).
		// Skip when the line is itself a section header (roleChanged).
		if !matched && !roleChanged && isIndented(rawLine) && line != "" && currentRole != "" {
			classifyIndentedLine(&m, currentRole, line, indentedIndex)
			indentedIndex++
		}
	}
	return m
}

func applyWHOISMatch(m *Metadata, key, val string) {
	if applyRegistrarMatch(m, key, val) {
		return
	}
	if applyContactMatch(&m.Registrant, key, "reg_", val) {
		return
	}
	if applyContactMatch(&m.Admin, key, "admin_", val) {
		return
	}
	if applyContactMatch(&m.Tech, key, "tech_", val) {
		return
	}
	if applyContactMatch(&m.Billing, key, "billing_", val) {
		return
	}
	if applyContactMatch(&m.Abuse, key, "abuse_", val) {
		return
	}
	applyDomainMatch(m, key, val)
}

func applyRegistrarMatch(m *Metadata, key, val string) bool {
	switch key {
	case "registrar":
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
		return true
	case "url":
		if m.RegistrarURL == "" {
			m.RegistrarURL = val
		}
		return true
	case "whoisserver":
		if m.WhoisServer == "" {
			m.WhoisServer = val
		}
		return true
	case "ianaid":
		if m.IANAID == "" {
			m.IANAID = val
		}
		return true
	case "dnssec":
		if m.DNSSEC == "" {
			m.DNSSEC = val
		}
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
	case "org":
		c.Organization = appendUnique(c.Organization, val)
		return true
	case "name":
		c.Name = appendUnique(c.Name, val)
		return true
	case "email":
		c.Email = appendUnique(c.Email, val)
		return true
	case "addr":
		c.Address = appendUnique(c.Address, val)
		return true
	case "phone":
		c.Phone = appendUnique(c.Phone, val)
		return true
	}
	return false
}

func applyDomainMatch(m *Metadata, key, val string) {
	switch key {
	case "creation":
		if m.CreationDate == "" {
			m.CreationDate = val
		}
	case "updated":
		if m.UpdatedDate == "" {
			m.UpdatedDate = val
		}
	case "expiration":
		if m.ExpirationDate == "" {
			m.ExpirationDate = val
		}
	case "ns":
		m.NameServers = append(m.NameServers, strings.ToLower(val))
	case "status":
		m.DomainStatus = append(m.DomainStatus, val)
	}
}
