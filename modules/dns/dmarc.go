package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getDMARCData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetDMARC)

	log.Printf("get_dmarc starting query for target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	dmarcTarget := "_dmarc." + target

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		txts, err := r.LookupTXT(fallbackCtx, dmarcTarget)
		if err != nil {
			return nil, fmt.Errorf("plain lookup dmarc failed: %w", err)
		}
		return txts, nil
	}

	records, raw, err := resolver.ResolveRecord(queryCtx, dmarcTarget, 16, plainFallback)
	if err != nil {
		log.Printf("get_dmarc error for target=%q: %v", target, err)
		modutil.SetError(&exec, "dmarc lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFallback(&exec, raw, records, ", ")

	dmarcRecords := filterDMARC(records)

	if len(dmarcRecords) == 0 {
		return exec
	}

	for _, rec := range dmarcRecords {
		dmarcRes := schema.ModuleResult{
			Type:     constants.TypeDMARC,
			Category: constants.CategoryProperty,
			Value:    rec,
		}
		exec.Results = append(exec.Results, dmarcRes)

		parsed := dnsutils.ParseDMARC(rec)
		source := &schema.EntityRef{Type: dmarcRes.Type, Value: dmarcRes.Value}
		exec.Results = append(exec.Results, processDMARCEmails(target, parsed, source)...)
	}

	log.Printf("get_dmarc success for target=%q results=%d", target, len(exec.Results))

	return exec
}

func filterDMARC(records []string) []string {
	var dmarc []string
	for _, rec := range records {
		rec = strings.Trim(strings.TrimSpace(rec), "\"")
		if strings.HasPrefix(rec, "v=DMARC1") {
			dmarc = append(dmarc, rec)
		}
	}
	return dmarc
}

func processDMARCEmails(target string, parsed map[string]string, source *schema.EntityRef) []schema.ModuleResult {
	var results []schema.ModuleResult
	for _, key := range []string{"ruf", "rua"} {
		val, ok := parsed[key]
		if !ok {
			continue
		}
		emails := dnsutils.ExtractDMARCEmails(val)
		for i, email := range emails {
			validatedEmail, err := validator.Validate(constants.TypeEmail, email)
			if err != nil {
				log.Printf("get_dmarc skipping invalid email target=%q entity=%q err=%v", target, email, err)
				continue
			}

			isOOS := orgdomain.IsEmailOutOfScope(validatedEmail.Value, target)
			log.Printf("get_dmarc target=%q email=%q normalized=%q type=%q oos=%v", target, email, validatedEmail.Value, validatedEmail.Type, isOOS)

			contextMsg := "DMARC " + strings.ToUpper(key)
			if len(emails) > 1 {
				contextMsg = fmt.Sprintf("DMARC %s #%d", strings.ToUpper(key), i+1)
			}

			results = append(results, schema.ModuleResult{
				Type:       validatedEmail.Type,
				Category:   constants.CategoryNode,
				Value:      validatedEmail.Value,
				Context:    contextMsg,
				OutOfScope: isOOS,
				Source:     source,
			})
		}
	}
	return results
}
