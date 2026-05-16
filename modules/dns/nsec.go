package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
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
	exec := modutil.NewExecution(constants.FuncGetNSEC)
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
	rec.Name = strings.TrimSuffix(rec.Name, ".")

	nsecRes := schema.ModuleResult{
		Type:     constants.TypeNSEC,
		Category: constants.CategoryProperty,
		Value:    rec.Name + " NSEC3 " + rec.Data,
		Context:  contextDesc,
	}
	results := []schema.ModuleResult{nsecRes}
	source := &schema.EntityRef{Type: nsecRes.Type, Value: nsecRes.Value}

	if hashPart := dnsutils.ExtractNSEC3Hash(rec.Name); hashPart != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeNSEC,
			Category: constants.CategoryProperty,
			Value:    hashPart,
			Context:  "NSEC3 Hash",
			Source:   source,
		})
	}

	if nextHash := dnsutils.ParseNSEC3(rec.Data); nextHash != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeNSEC,
			Category: constants.CategoryProperty,
			Value:    nextHash,
			Context:  "NSEC3 Next Hash",
			Source:   source,
		})
	}

	return results
}

func parseNSECRecord(rec resolver.DoHDnsRecord, target, nxTarget, contextDesc string) []schema.ModuleResult {
	rec.Name = strings.TrimSuffix(rec.Name, ".")
	parts := strings.Fields(rec.Data)
	if len(parts) > 0 {
		parts[0] = strings.TrimSuffix(parts[0], ".")
		rec.Data = strings.Join(parts, " ")
	}

	var results []schema.ModuleResult

	var nsecSource *schema.EntityRef
	if r := extractNSECDomain(rec.Name, target, nxTarget, "NSEC Current Subdomain"); r != nil {
		results = append(results, *r)
		nsecSource = &schema.EntityRef{Type: r.Type, Value: r.Value}
		log.Printf("get_nsec target=%q current=%q oos=%v", target, r.Value, r.OutOfScope)
	}

	nsecRes := schema.ModuleResult{
		Type:     constants.TypeNSEC,
		Category: constants.CategoryProperty,
		Value:    rec.Name + " NSEC " + rec.Data,
		Context:  contextDesc,
		Source:   nsecSource,
	}
	results = append(results, nsecRes)

	nsecPropertyRef := &schema.EntityRef{Type: nsecRes.Type, Value: nsecRes.Value}
	if nextDomain := dnsutils.ParseNSEC(rec.Data); nextDomain != "" {
		if r := extractNSECDomain(nextDomain, target, nxTarget, "NSEC Leaked Subdomain"); r != nil {
			r.Source = nsecPropertyRef
			log.Printf("get_nsec target=%q leaked=%q oos=%v", target, r.Value, r.OutOfScope)
			results = append(results, *r)
		}
	}

	return results
}

func extractNSECDomain(raw, target, nxTarget, contextDesc string) *schema.ModuleResult {
	domain := strings.TrimSuffix(raw, ".")
	if domain == "" {
		return nil
	}

	isWildcard := strings.HasPrefix(domain, "*.")
	cleanDomain := domain
	if isWildcard {
		cleanDomain = strings.TrimPrefix(domain, "*.")
	}

	if _, err := validator.Validate(constants.TypeDomain, cleanDomain); err != nil {
		return nil
	}

	if !isWildcard && (strings.EqualFold(cleanDomain, target) || strings.EqualFold(cleanDomain, nxTarget)) {
		return nil
	}

	org := orgdomain.GetOrganizationalDomain(cleanDomain)
	if org == "" {
		org = cleanDomain
	}

	resType := constants.TypeSubdomain
	if strings.EqualFold(cleanDomain, org) {
		resType = constants.TypeDomain
	}

	result := schema.ModuleResult{
		Type:       resType,
		Category:   constants.CategoryNode,
		Value:      cleanDomain,
		Context:    contextDesc,
		OutOfScope: orgdomain.IsOutOfScope(cleanDomain, target),
		Tags:       []string{constants.TagNSEC},
	}
	if isWildcard {
		result.Tags = append(result.Tags, constants.TagWildcard)
		result.Context = domain
	}

	return &result
}
