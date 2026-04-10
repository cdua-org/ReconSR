package dispatcher

import (
	"cdua-org/ReconSR/modules/asn_metadata"
	"cdua-org/ReconSR/modules/dns"
	"cdua-org/ReconSR/modules/domainsbycerts"
	"cdua-org/ReconSR/modules/hackertarget"
	"cdua-org/ReconSR/modules/ip_metadata"
	"cdua-org/ReconSR/modules/ipv4ambiguous"
	"cdua-org/ReconSR/modules/mailcrypto"
	"cdua-org/ReconSR/modules/subdomain_hierarchy"
	"cdua-org/ReconSR/modules/whois"
	"cdua-org/ReconSR/schema"
)

type module struct {
	name string
	exec func(schema.ModuleInput) (schema.ModuleOutput, error)
	caps func() (schema.ModuleCapabilities, error)
}

func (m *module) Name() string {
	return m.name
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	return m.exec(data)
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.caps == nil {
		return schema.ModuleCapabilities{}, nil
	}
	return m.caps()
}

var ModuleRegistry = []schema.Module{
	&module{name: "subdomain_hierarchy", exec: subdomain_hierarchy.HandleData, caps: subdomain_hierarchy.GetCapabilities},
	whois.New(),
	domainsbycerts.New(),
	hackertarget.New(),
	ip_metadata.New(),
	asn_metadata.New(),
	dns.New(),
	mailcrypto.New(),
	ipv4ambiguous.New(),
}
