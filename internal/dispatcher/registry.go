package dispatcher

import (
	"cdua-org/ReconSR/modules/ipv4ambiguous"
	"cdua-org/ReconSR/modules/subdomain_hierarchy"
	"cdua-org/ReconSR/schema"
)

var ModuleRegistry = []schema.Module{
	subdomain_hierarchy.New(),
	ipv4ambiguous.New(),
}
