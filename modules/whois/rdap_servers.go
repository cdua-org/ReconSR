package whois

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ianaRDAPServers   map[string]string
	ianaRDAPBootstrap sync.Once
)

type serviceEntry struct {
	URL  string
	TLDs []string
}

func initRDAPServers() {
	ianaRDAPBootstrap.Do(func() {
		ianaRDAPServers = make(map[string]string)

		services := fetchIANABootstrap()
		for _, svc := range services {
			for _, tld := range svc.TLDs {
				ianaRDAPServers[tld] = svc.URL
			}
		}
	})
}

func fetchIANABootstrap() []serviceEntry {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://data.iana.org/rdap/dns.json", http.NoBody)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	cErr := resp.Body.Close()
	if err != nil || cErr != nil {
		return nil
	}

	var raw struct {
		Services [][][]any `json:"services"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	var services []serviceEntry

	for _, service := range raw.Services {
		entry := parseServiceEntry(service)
		if entry != nil {
			services = append(services, *entry)
		}
	}

	return services
}

func parseServiceEntry(service [][]any) *serviceEntry {
	if len(service) < 2 {
		return nil
	}

	url := extractHTTPSURL(service[1])
	if url == "" {
		return nil
	}

	tlds := extractTLDs(service[0])
	if len(tlds) == 0 {
		return nil
	}

	return &serviceEntry{TLDs: tlds, URL: url}
}

func extractHTTPSURL(urls []any) string {
	for _, u := range urls {
		if strURL, ok := u.(string); ok && strings.HasPrefix(strURL, "https://") {
			return strURL
		}
	}
	return ""
}

func extractTLDs(tlds []any) []string {
	var result []string
	for _, t := range tlds {
		if tld, ok := t.(string); ok {
			result = append(result, tld)
		}
	}
	return result
}

func getRDAPServer(tld string) string {
	// 1. Check manual overrides for unlisted ccTLDs
	if server, ok := customRDAPServers[tld]; ok {
		return server
	}

	// 2. Check official IANA bootstrap registry
	initRDAPServers()
	if server, ok := ianaRDAPServers[tld]; ok {
		return server
	}

	// 3. Fallback to rdap.org (returns empty string, caller uses rdap.org)
	return ""
}

// Manual RDAP server overrides for TLDs not in IANA bootstrap but verified working.
var customRDAPServers = map[string]string{
	"de": "https://rdap.denic.de/",
	"ch": "https://rdap.nic.ch/",
	"li": "https://rdap.nic.li/",
	"kz": "https://rdap.nic.kz/",
}
