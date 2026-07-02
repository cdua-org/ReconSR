package whois

import (
	"slices"
	"strings"
)

func applyNOMatch(m *Metadata, key, val string) {
	switch key {
	case "no_registrar":
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
	case "no_tech":
		m.Tech.Name = appendUnique(m.Tech.Name, val)
	case "no_nserver":
		val = strings.TrimSpace(val)
		if val != "" && !slices.Contains(m.NameServers, val) {
			m.NameServers = append(m.NameServers, val)
		}
	}
}
