package domainsbycerts

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
)

type crtshRecord struct {
	NameValue string `json:"name_value"`
	NotAfter  string `json:"not_after"`
}

var crtshBaseURL = "https://crt.sh"

type crtshFetcher struct{}

func newCrtshFetcher() CertFetcher {
	return &crtshFetcher{}
}

func (f *crtshFetcher) Name() string {
	return "crt.sh"
}

func (f *crtshFetcher) Fetch(ctx context.Context, target string) []certificateIdentityEntry {
	u := crtshBaseURL + "/?q=%25." + url.QueryEscape(target) + "&output=json"
	body, err := doRequestWithRetry(ctx, u)
	if err != nil {
		return nil
	}

	var records []crtshRecord
	if err := json.Unmarshal(body, &records); err != nil {
		dbg.Printf("%s error source=%q target=%q stage=unmarshal err=%v", constants.FuncGetDomains, f.Name(), target, err)
		return nil
	}

	var entries []certificateIdentityEntry
	for _, rec := range records {
		notAfter := parseCertTimestamp(rec.NotAfter)
		for name := range strings.SplitSeq(rec.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			entries = append(entries, certificateIdentityEntry{
				value:    name,
				notAfter: notAfter,
				rawData:  body,
			})
		}
	}
	return entries
}
