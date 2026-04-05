package domainsbycerts

import (
	"context"
	"encoding/json"
	"net/url"
)

type certspotterResponse struct {
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DNSNames  []string `json:"dns_names"`
}

type certspotterFetcher struct{}

func newCertspotterFetcher() CertFetcher {
	return &certspotterFetcher{}
}

func (f *certspotterFetcher) Name() string {
	return "Certspotter"
}

func (f *certspotterFetcher) Fetch(ctx context.Context, target string) []domainEntry {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(target) + "&include_subdomains=true&expand=dns_names"
	body, err := doRequestWithRetry(ctx, u)
	if err != nil {
		return nil
	}

	var records []certspotterResponse
	if err := json.Unmarshal(body, &records); err != nil {
		return nil
	}

	var entries []domainEntry
	for _, rec := range records {
		notAfter := parseCertTimestamp(rec.NotAfter)
		for _, name := range rec.DNSNames {
			entries = append(entries, domainEntry{
				domain:   name,
				notAfter: notAfter,
				rawData:  body,
			})
		}
	}
	return entries
}
