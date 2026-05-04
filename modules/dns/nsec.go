package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

type nsecQuery struct {
	queryTarget string
	contextDesc string
	qtype       int
}

func getNSECData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_nsec")
	log.Printf("get_nsec target=%q", target)

	bruteCtx, cancel := context.WithTimeout(ctx, resolver.DNSBruteTimeout)
	defer cancel()

	if strings.HasPrefix(strings.ToLower(target), "nx-") {
		log.Printf("get_nsec target=%q skipped (nx- prefix)", target)
		return exec
	}

	bytes := make([]byte, 6)
	_, _ = rand.Read(bytes)
	nxTarget := "nx-" + hex.EncodeToString(bytes) + "." + target

	queries := []nsecQuery{
		{target, "Direct NSEC", 47},
		{target, "Direct NSEC3", 50},
		{nxTarget, "Zone Walk NXDOMAIN", 1},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var rawDataBuilder strings.Builder

	for _, req := range queries {
		wg.Go(func() {
			results, raw := executeNSECQuery(bruteCtx, req, target, nxTarget)

			mu.Lock()
			defer mu.Unlock()

			if len(raw) > 0 {
				if rawDataBuilder.Len() > 0 {
					rawDataBuilder.WriteString("\n")
				}
				rawDataBuilder.Write(raw)
			}

			exec.Results = append(exec.Results, results...)
		})
	}

	wg.Wait()

	if rawDataBuilder.Len() > 0 {
		exec.RawData = rawDataBuilder.String()
	}

	log.Printf("get_nsec target=%q results=%d", target, len(exec.Results))
	return exec
}

func executeNSECQuery(ctx context.Context, q nsecQuery, target, nxTarget string) (results []schema.ModuleResult, raw []byte) {
	resp, raw, err := resolver.QueryDoHDns(ctx, q.queryTarget, q.qtype)
	if err != nil {
		log.Printf("get_nsec query=%q qtype=%d error: %v", q.queryTarget, q.qtype, err)
		return nil, nil
	}
	if resp == nil {
		return nil, nil
	}

	results = collectNSECRecords(resp.Answer, target, nxTarget, q.contextDesc)
	if resp.Status == 3 || q.qtype == 1 {
		results = append(results, collectNSECRecords(resp.Authority, target, nxTarget, q.contextDesc)...)
	}

	return results, raw
}

func collectNSECRecords(records []resolver.DoHDnsRecord, target, nxTarget, contextDesc string) []schema.ModuleResult {
	var results []schema.ModuleResult
	for _, rec := range records {
		switch rec.Type {
		case 47:
			results = append(results, parseNSECRecord(rec, target, nxTarget, contextDesc)...)
		case 50:
			results = append(results, parseNSEC3Record(rec, contextDesc)...)
		}
	}
	return results
}

func parseNSEC3Record(rec resolver.DoHDnsRecord, contextDesc string) []schema.ModuleResult {
	results := []schema.ModuleResult{
		{
			Type:     "nsec",
			Category: "property",
			Value:    rec.Name + " NSEC3 " + rec.Data,
			Context:  contextDesc,
		},
	}

	hashPart, _, _ := strings.Cut(rec.Name, ".")
	results = append(results, schema.ModuleResult{
		Type:     "nsec",
		Category: "property",
		Value:    hashPart,
		Context:  "NSEC3 Hash",
	})

	parts := strings.Fields(rec.Data)
	if len(parts) >= 5 {
		results = append(results, schema.ModuleResult{
			Type:     "nsec",
			Category: "property",
			Value:    parts[4],
			Context:  "NSEC3 Next Hash",
		})
	}

	return results
}

func parseNSECRecord(rec resolver.DoHDnsRecord, target, nxTarget, contextDesc string) []schema.ModuleResult {
	results := []schema.ModuleResult{
		{
			Type:     "nsec",
			Category: "property",
			Value:    rec.Name + " NSEC " + rec.Data,
			Context:  contextDesc,
		},
	}

	parts := strings.Fields(rec.Data)
	if len(parts) > 0 {
		if r := extractNSECDomain(parts[0], target, nxTarget, "NSEC Leaked Subdomain"); r != nil {
			log.Printf("get_nsec target=%q leaked=%q oos=%v", target, r.Value, r.OutOfScope)
			results = append(results, *r)
		}
	}

	if r := extractNSECDomain(rec.Name, target, nxTarget, "NSEC Current Subdomain"); r != nil {
		log.Printf("get_nsec target=%q current=%q oos=%v", target, r.Value, r.OutOfScope)
		results = append(results, *r)
	}

	return results
}

func extractNSECDomain(raw, target, nxTarget, contextDesc string) *schema.ModuleResult {
	domain := strings.TrimSuffix(raw, ".")
	if domain == "" {
		return nil
	}

	if _, err := validator.Validate("domain", domain); err != nil {
		return nil
	}

	if strings.EqualFold(domain, target) || strings.EqualFold(domain, nxTarget) {
		return nil
	}

	if !strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(target)) {
		return nil
	}

	isWildcard := strings.HasPrefix(domain, "*.")
	cleanDomain := domain
	if isWildcard {
		cleanDomain = strings.TrimPrefix(domain, "*.")
	}

	org := orgdomain.GetOrganizationalDomain(cleanDomain)
	if org == "" {
		org = cleanDomain
	}

	resType := "subdomain"
	if strings.EqualFold(cleanDomain, org) {
		resType = "domain"
	}

	if isWildcard {
		if resType == "domain" {
			resType = "wildcard_domain"
		} else {
			resType = "wildcard_subdomain"
		}
	}

	return &schema.ModuleResult{
		Type:       resType,
		Category:   "node",
		Value:      domain,
		Context:    contextDesc,
		OutOfScope: orgdomain.IsOutOfScope(domain, target),
	}
}
