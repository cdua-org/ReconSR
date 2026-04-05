package dispatcher

import (
	"cdua-org/ReconSR/modules/dns"
	"cdua-org/ReconSR/modules/dns_caa"
	"cdua-org/ReconSR/modules/dns_cname"
	"cdua-org/ReconSR/modules/dns_dkim"
	"cdua-org/ReconSR/modules/dns_dmarc"
	"cdua-org/ReconSR/modules/dns_domainkey"
	"cdua-org/ReconSR/modules/dns_mx"
	"cdua-org/ReconSR/modules/dns_ns"
	"cdua-org/ReconSR/modules/dns_soa"
	"cdua-org/ReconSR/modules/dns_txt"
	"cdua-org/ReconSR/modules/dns_wildcard"
	"cdua-org/ReconSR/modules/domainsbycerts"
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
	dns_wildcard.New(),
	dns.New(),
	dns_caa.New(),
	dns_soa.New(),
	dns_mx.New(),
	dns_dmarc.New(),
	dns_domainkey.New(),
	dns_dkim.New(),
	dns_cname.New(),
	dns_ns.New(),
	dns_txt.New(),
}
