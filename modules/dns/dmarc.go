package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getDMARCData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_dmarc")

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
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "dmarc",
			Category: "property",
			Value:    rec,
		})

		parsed := parseDMARC(rec)

		exec.Results = append(exec.Results, processDMARCEmails(target, parsed)...)
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

func parseDMARC(record string) map[string]string {
	result := make(map[string]string)

	record = strings.TrimSpace(record)
	for part := range strings.SplitSeq(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			result[key] = value
		}
	}

	return result
}

func extractEmails(val string) []string {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "mailto:")

	var emails []string
	for part := range strings.SplitSeq(val, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "mailto:")
		if part != "" && strings.Contains(part, "@") {
			emails = append(emails, part)
		}
	}
	return emails
}

func processDMARCEmails(target string, parsed map[string]string) []schema.ModuleResult {
	var results []schema.ModuleResult
	for _, key := range []string{"ruf", "rua"} {
		val, ok := parsed[key]
		if !ok {
			continue
		}
		emails := extractEmails(val)
		for i, email := range emails {
			validatedEmail, err := validator.Validate("email", email)
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
				Category:   "node",
				Value:      validatedEmail.Value,
				Context:    contextMsg,
				OutOfScope: isOOS,
			})
		}
	}
	return results
}
