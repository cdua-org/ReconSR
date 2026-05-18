package domainsbycerts

import (
	"context"
	"encoding/json"
	"net/url"

	"cdua-org/ReconSR/modules/utils/constants"
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

func (f *certspotterFetcher) Fetch(ctx context.Context, target string) []certificateIdentityEntry {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(target) + "&include_subdomains=true&expand=dns_names"
	body, err := doRequestWithRetry(ctx, u)
	if err != nil {
		return nil
	}

	var records []certspotterResponse
	if err := json.Unmarshal(body, &records); err != nil {
		dbg.Printf("%s error source=%q target=%q stage=unmarshal err=%v", constants.FuncGetDomains, f.Name(), target, err)
		return nil
	}

	var entries []certificateIdentityEntry
	for _, rec := range records {
		notAfter := parseCertTimestamp(rec.NotAfter)
		for _, name := range rec.DNSNames {
			entries = append(entries, certificateIdentityEntry{
				value:    name,
				notAfter: notAfter,
				rawData:  body,
			})
		}
	}
	return entries
}
