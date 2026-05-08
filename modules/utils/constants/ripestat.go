package constants

// RIPEstatEndpointASNNeighbours and related constants define canonical RIPEstat endpoint identifiers so metadata modules query the same upstream resources without duplicating literals.
const (
	RIPEstatEndpointASNNeighbours      = "asn-neighbours"
	RIPEstatEndpointAnnouncedPrefixes  = "announced-prefixes"
	RIPEstatEndpointASOverview         = "as-overview"
	RIPEstatEndpointAbuseContactFinder = "abuse-contact-finder"
)
