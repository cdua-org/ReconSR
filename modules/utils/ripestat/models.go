// Package ripestat provides a client for the RIPEstat API.
package ripestat

// Neighbour represents an ASN peering neighbour.
type Neighbour struct {
	Position  string `json:"type"`
	ASN       int    `json:"asn"`
	PathCount int    `json:"power"`
	PeerCount int    `json:"v4_peers"`
}

// APIResponse represents the asn-neighbours response.
type APIResponse struct {
	RawJSON string `json:"-"`
	Data    struct {
		Neighbours []Neighbour `json:"neighbours"`
	} `json:"data"`
}

func (r *APIResponse) setRawJSON(raw string) { r.RawJSON = raw }

// AnnouncedPrefixesResponse represents the announced-prefixes response.
type AnnouncedPrefixesResponse struct {
	RawJSON string `json:"-"`
	Data    struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func (r *AnnouncedPrefixesResponse) setRawJSON(raw string) { r.RawJSON = raw }

// ASOverviewResponse represents the as-overview response.
type ASOverviewResponse struct {
	RawJSON string `json:"-"`
	Data    struct {
		Holder string `json:"holder"`
	} `json:"data"`
}

func (r *ASOverviewResponse) setRawJSON(raw string) { r.RawJSON = raw }

// AbuseContactResponse represents the abuse-contact-finder response.
type AbuseContactResponse struct {
	RawJSON string `json:"-"`
	Data    struct {
		AbuseContacts []string `json:"abuse_contacts"`
	} `json:"data"`
}

func (r *AbuseContactResponse) setRawJSON(raw string) { r.RawJSON = raw }

// WhoisResponse represents the whois endpoint response.
type WhoisResponse struct {
	RawJSON string `json:"-"`
	Data    struct {
		Records [][]struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"records"`
	} `json:"data"`
}

func (r *WhoisResponse) setRawJSON(raw string) { r.RawJSON = raw }
