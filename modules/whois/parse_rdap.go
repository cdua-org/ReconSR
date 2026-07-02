package whois

import (
	"slices"
	"strings"
)

func parseRDAP(data map[string]any) Metadata {
	m := Metadata{}
	if entities, ok := data["entities"].([]any); ok {
		parseRDAPEntities(&m, entities)
	}
	if events, ok := data["events"].([]any); ok {
		parseRDAPEvents(&m, events)
	}
	if ns, ok := data["nameservers"].([]any); ok {
		parseRDAPNameservers(&m, ns)
	}
	if status, ok := data["status"].([]any); ok {
		parseRDAPStatus(&m, status)
	}
	return m
}

func parseRDAPEntities(m *Metadata, entities []any) {
	for _, e := range entities {
		entity, ok := e.(map[string]any)
		if !ok {
			continue
		}

		if subEntities, subOk := entity["entities"].([]any); subOk {
			parseRDAPEntities(m, subEntities)
		}

		roles, ok := entity["roles"].([]any)
		if !ok {
			continue
		}
		for _, r := range roles {
			role, ok := r.(string)
			if !ok {
				continue
			}
			vcards, ok := entity["vcardArray"].([]any)
			if !ok || len(vcards) <= 1 {
				continue
			}
			props, ok := vcards[1].([]any)
			if !ok {
				continue
			}
			extractVCardProps(m, role, props)
		}
	}
}

func extractVCardProps(m *Metadata, role string, props []any) {
	var targetContact *Contact
	switch role {
	case whoisRoleRegistrar:
		targetContact = &m.Registrar
	case whoisRoleRegistrant:
		targetContact = &m.Registrant
	case whoisRoleAdministrative:
		targetContact = &m.Admin
	case whoisRoleTechnical:
		targetContact = &m.Tech
	case whoisRoleBilling:
		targetContact = &m.Billing
	case whoisRoleAbuse:
		targetContact = &m.Abuse
	default:
		return
	}

	for _, p := range props {
		applyVCardProp(m, targetContact, role, p)
	}
}

func applyVCardProp(m *Metadata, c *Contact, role string, p any) {
	prop, ok := p.([]any)
	if !ok || len(prop) < 4 {
		return
	}
	name := safeString(prop[0])
	value := safeString(prop[3])

	switch name {
	case "fn":
		c.Name = appendUnique(c.Name, value)
	case whoisFieldOrg:
		c.Organization = appendUnique(c.Organization, value)
	case whoisFieldEmail:
		c.Email = appendUnique(c.Email, value)
	case "adr":
		c.Address = appendUnique(c.Address, value)
	case "tel":
		c.Phone = appendUnique(c.Phone, value)
	case whoisFieldURL:
		if role == whoisRoleRegistrar {
			m.RegistrarURL = value
		}
	}
}

func parseRDAPEvents(m *Metadata, events []any) {
	for _, e := range events {
		event, ok := e.(map[string]any)
		if !ok {
			continue
		}
		action := safeString(event["eventAction"])
		date := safeString(event["eventDate"])

		switch action {
		case "registration":
			m.CreationDate = date
		case whoisFieldExpiration:
			m.ExpirationDate = date
		case "last changed":
			m.UpdatedDate = date
		}
	}
}

func parseRDAPNameservers(m *Metadata, ns []any) {
	for _, n := range ns {
		entry, ok := n.(map[string]any)
		if !ok {
			continue
		}
		host := safeString(entry["ldhName"])
		if host == "" {
			continue
		}
		if idx := strings.Index(host, " ["); idx > 0 {
			host = host[:idx]
		}
		host = strings.ToLower(host)
		if !slices.Contains(m.NameServers, host) {
			m.NameServers = append(m.NameServers, host)
		}
	}
}

func parseRDAPStatus(m *Metadata, status []any) {
	for _, s := range status {
		if str := safeString(s); str != "" {
			m.DomainStatus = append(m.DomainStatus, str)
		}
	}
}
