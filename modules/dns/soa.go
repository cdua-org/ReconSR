package dns

import (
	"context"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getSOAData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetSOA)

	log.Printf("get_soa query target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 6, nil)
	if err != nil {
		log.Printf("get_soa error target=%q err=%v", target, err)
		modutil.SetError(&exec, "soa lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	var soaRaw string
	var soa *dnsutils.SOA
	for _, rec := range records {
		soa = dnsutils.ParseSOA(rec)
		if soa != nil {
			soaRaw = rec
			break
		}
	}

	if soa == nil {
		return exec
	}

	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: soaRaw}

	exec.Results = append(exec.Results,
		schema.ModuleResult{Type: constants.TypeSOA, Category: constants.CategoryProperty, Value: soaRaw},
		schema.ModuleResult{Type: constants.TypeSOA, Category: constants.CategoryProperty, Value: strconv.FormatUint(uint64(soa.Serial), 10), Context: "Serial", Source: soaRef},
	)

	if result := buildSOAPrimaryNSResult(soa.NS, target, soaRef); result != nil {
		exec.Results = append(exec.Results, *result)
	}

	if result := buildSOAResponsibleEmailResult(soa.Mbox, target, soaRef); result != nil {
		exec.Results = append(exec.Results, *result)
	}

	log.Printf("get_soa success target=%q results=%d", target, len(exec.Results))

	return exec
}

func buildSOAPrimaryNSResult(rawNS, target string, source *schema.EntityRef) *schema.ModuleResult {
	primaryNS := strings.TrimSuffix(rawNS, ".")
	res, err := validator.Validate(constants.TypeDomain, primaryNS)
	if err != nil {
		log.Printf("get_soa skipping invalid primary ns target=%q entity=%q err=%v", target, primaryNS, err)
		return nil
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	log.Printf("get_soa target=%q entity=%q oos=%v", target, res.Value, isOOS)

	return &schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagNS},
		Context:    "Primary NS",
		OutOfScope: isOOS,
		Source:     source,
	}
}

func buildSOAResponsibleEmailResult(rawMbox, target string, source *schema.EntityRef) *schema.ModuleResult {
	responsibleEmail := dnsutils.FormatSOAMbox(rawMbox)
	res, err := validator.Validate(constants.TypeEmail, responsibleEmail)
	if err != nil {
		log.Printf("get_soa skipping invalid responsible email target=%q email=%q err=%v", target, responsibleEmail, err)
		return nil
	}

	isOOS := orgdomain.IsEmailOutOfScope(res.Value, target)
	log.Printf("get_soa target=%q email=%q oos=%v", target, res.Value, isOOS)

	return &schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Context:    "Responsible Email",
		OutOfScope: isOOS,
		Source:     source,
	}
}
