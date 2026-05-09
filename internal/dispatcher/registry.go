package dispatcher

import (
	"cdua-org/ReconSR/modules/anubis"
	"cdua-org/ReconSR/modules/asn_metadata"
	"cdua-org/ReconSR/modules/dns"
	"cdua-org/ReconSR/modules/domainsbycerts"
	"cdua-org/ReconSR/modules/emailformat"
	"cdua-org/ReconSR/modules/hackertarget"
	"cdua-org/ReconSR/modules/ip_metadata"
	"cdua-org/ReconSR/modules/ipv4ambiguous"
	"cdua-org/ReconSR/modules/mailcrypto"
	"cdua-org/ReconSR/modules/shodan"
	"cdua-org/ReconSR/modules/subdomain_hierarchy"
	"cdua-org/ReconSR/modules/virustotal"
	"cdua-org/ReconSR/modules/whois"
	"cdua-org/ReconSR/schema"
)

var ModuleRegistry = []schema.Module{
	anubis.New(),
	asn_metadata.New(),
	dns.New(),
	domainsbycerts.New(),
	emailformat.New(),
	hackertarget.New(),
	ip_metadata.New(),
	ipv4ambiguous.New(),
	mailcrypto.New(),
	shodan.New(),
	subdomain_hierarchy.New(),
	virustotal.New(),
	whois.New(),
}
