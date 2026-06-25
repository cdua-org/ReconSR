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

func getNSECData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetNSEC)
	log.Printf("%s query_start target=%q", constants.FuncGetNSEC, target)

	bruteCtx, cancel := context.WithTimeout(ctx, resolver.DNSBruteTimeout)
	defer cancel()

	if strings.HasPrefix(strings.ToLower(target), "nx-") {
		log.Printf("%s skip_prefixed_target target=%q prefix=%q", constants.FuncGetNSEC, target, "nx-")
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
			results, raw := executeNSECQuery(bruteCtx, req, target, nxTarget, gen)

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

	log.Printf("%s success target=%q results=%d", constants.FuncGetNSEC, target, len(exec.Results))
	return exec
}

func executeNSECQuery(ctx context.Context, q nsecQuery, target, nxTarget string, gen *modutil.LocalIDGenerator) (results []schema.ModuleResult, raw []byte) {
	resp, raw, err := queryDoHDnsFunc(ctx, q.queryTarget, q.qtype)
	if err != nil {
		log.Printf("%s error target=%q query=%q qtype=%d stage=query_doh err=%v", constants.FuncGetNSEC, target, q.queryTarget, q.qtype, err)
		return nil, nil
	}
	if resp == nil {
		return nil, nil
	}

	results = collectNSECRecords(resp.Answer, target, nxTarget, q.contextDesc, gen)
	if resp.Status == 3 || q.qtype == 1 {
		results = append(results, collectNSECRecords(resp.Authority, target, nxTarget, q.contextDesc, gen)...)
	}

	return results, raw
}

func collectNSECRecords(records []resolver.DoHDnsRecord, target, nxTarget, contextDesc string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	var results []schema.ModuleResult
	for _, rec := range records {
		switch rec.Type {
		case 47:
			results = append(results, parseNSECRecord(rec, target, nxTarget, contextDesc, gen)...)
		case 50:
			results = append(results, parseNSEC3Record(rec, contextDesc, gen)...)
		}
	}
	return results
}

func parseNSEC3Record(rec resolver.DoHDnsRecord, contextDesc string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	rec.Name = strings.TrimSuffix(rec.Name, ".")

	nsecRes := schema.ModuleResult{
		Type:     constants.TypeNSEC,
		Category: constants.CategoryProperty,
		Value:    rec.Name + " NSEC3 " + rec.Data,
		Context:  contextDesc,
		LocalID:  gen.NextID(),
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
			LocalID:  gen.NextID(),
		})
	}

	if nextHash := dnsutils.ParseNSEC3(rec.Data); nextHash != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeNSEC,
			Category: constants.CategoryProperty,
			Value:    nextHash,
			Context:  "NSEC3 Next Hash",
			Source:   source,
			LocalID:  gen.NextID(),
		})
	}

	return results
}

func parseNSECRecord(rec resolver.DoHDnsRecord, target, nxTarget, contextDesc string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	rec.Name = strings.TrimSuffix(rec.Name, ".")
	parts := strings.Fields(rec.Data)
	if len(parts) > 0 {
		parts[0] = strings.TrimSuffix(parts[0], ".")
		rec.Data = strings.Join(parts, " ")
	}

	var results []schema.ModuleResult

	var nsecSource *schema.EntityRef
	if r := extractNSECDomain(rec.Name, target, nxTarget, "NSEC Current Subdomain", gen); r != nil {
		results = append(results, *r)
		nsecSource = &schema.EntityRef{Type: r.Type, Value: r.Value}
		log.Printf("%s result_current target=%q entity=%q oos=%v", constants.FuncGetNSEC, target, r.Value, r.OutOfScope)
	}

	nsecRes := schema.ModuleResult{
		Type:     constants.TypeNSEC,
		Category: constants.CategoryProperty,
		Value:    rec.Name + " NSEC " + rec.Data,
		Context:  contextDesc,
		Source:   nsecSource,
		LocalID:  gen.NextID(),
	}
	results = append(results, nsecRes)

	nsecPropertyRef := &schema.EntityRef{Type: nsecRes.Type, Value: nsecRes.Value}
	if nextDomain := dnsutils.ParseNSEC(rec.Data); nextDomain != "" {
		if r := extractNSECDomain(nextDomain, target, nxTarget, "NSEC Leaked Subdomain", gen); r != nil {
			r.Source = nsecPropertyRef
			log.Printf("%s result_leaked target=%q entity=%q oos=%v", constants.FuncGetNSEC, target, r.Value, r.OutOfScope)
			results = append(results, *r)
		}
	}

	return results
}

func extractNSECDomain(raw, target, nxTarget, contextDesc string, gen *modutil.LocalIDGenerator) *schema.ModuleResult {
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
		LocalID:    gen.NextID(),
	}
	if isWildcard {
		result.Tags = append(result.Tags, constants.TagWildcard)
		result.Context = domain
	}

	return &result
}
