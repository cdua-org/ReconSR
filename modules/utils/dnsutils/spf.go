package dnsutils

import (
	"net/netip"
	"strings"
)

// SPFEntityType classifies extracted SPF mechanism targets.
type SPFEntityType int

// SPFEntityIP4 and related constants classify SPF mechanism target types.
const (
	SPFEntityIP4 SPFEntityType = iota
	SPFEntityIP6
	SPFEntityDomain
)

// SPFEntity represents a single entity extracted from an SPF record.
type SPFEntity struct {
	Value     string
	Mechanism string
	Kind      SPFEntityType
}

// ParseSPF extracts OSINT-relevant entities (IPs and domains) from an SPF TXT record.
// It handles ip4, ip6, a, mx, include, redirect, and exists mechanisms per RFC 7208.
func ParseSPF(raw string) []SPFEntity {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(lower, "v=spf1") {
		return nil
	}

	var entities []SPFEntity
	for _, token := range strings.Fields(raw)[1:] {
		entity, ok := parseSPFToken(token)
		if ok {
			entities = append(entities, entity)
		}
	}
	return entities
}

func parseSPFToken(token string) (SPFEntity, bool) {
	token = strings.TrimLeft(token, "+-~?")

	for _, prefix := range []string{"ip4:", "ip6:"} {
		if strings.HasPrefix(strings.ToLower(token), prefix) {
			return parseSPFIPToken(token, prefix)
		}
	}

	for _, prefix := range []string{"include:", "a:", "mx:", "exists:", "redirect="} {
		if strings.HasPrefix(strings.ToLower(token), prefix) {
			return parseSPFDomainToken(token, prefix)
		}
	}

	return SPFEntity{}, false
}

func parseSPFIPToken(token, prefix string) (SPFEntity, bool) {
	value := token[len(prefix):]
	if value == "" {
		return SPFEntity{}, false
	}

	host := value
	if idx := strings.IndexByte(host, '/'); idx != -1 {
		host = host[:idx]
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return SPFEntity{}, false
	}

	kind := SPFEntityIP4
	if addr.Is6() {
		kind = SPFEntityIP6
	}

	return SPFEntity{
		Value:     value,
		Mechanism: strings.ToLower(prefix[:len(prefix)-1]),
		Kind:      kind,
	}, true
}

func parseSPFDomainToken(token, prefix string) (SPFEntity, bool) {
	value := token[len(prefix):]
	if idx := strings.IndexByte(value, '/'); idx != -1 {
		value = value[:idx]
	}
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")

	if value == "" || strings.ContainsAny(value, " \t\"") {
		return SPFEntity{}, false
	}

	mechanism := strings.ToLower(prefix)
	mechanism = strings.TrimRight(mechanism, ":=")

	return SPFEntity{
		Value:     value,
		Mechanism: mechanism,
		Kind:      SPFEntityDomain,
	}, true
}
